"""The UI helper host module (``core/uihelper.py``) against a scripted fake helper.

:class:`FakeHelper` stands in for ``adb -s S shell <helper>``: its stdout and
stderr are real ``os.pipe`` ends (read by the module's reader threads), and each
command written to its stdin is answered by a scripted handler. One-shot adb
calls go to :class:`FakeAdb` (``Adb.send_adb_command`` patched). The supervisor
gets a fake sleep and clock, so no test waits for a real back-off. Nothing runs
adb or touches a device.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import stat
import subprocess
import threading
import time
import zipfile
from importlib import resources
from pathlib import Path

import pytest

from sandroid.core import uihelper
from sandroid.core.adb import Adb
from sandroid.core.uihelper import Mode, UiHelper

SERIAL = "emu-1"
REPO = Path(__file__).resolve().parents[2]
PNG = uihelper._PNG_MAGIC + b"fake-png-body"


# --------------------------------------------------------------------- fakes


def wait_for(pred, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


class _Stdin:
    def __init__(self, proc: FakeHelper) -> None:
        self.proc = proc
        self.closed = False

    def write(self, data: bytes) -> int:
        if self.closed or self.proc.returncode is not None:
            raise BrokenPipeError("helper gone")
        for line in data.decode().splitlines():
            self.proc.on_command(line)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if not self.proc.hang_on_eof:
            self.proc.emit({"type": "bye"})
            self.proc.die(0)


class FakeHelper:
    """Scripted ``adb shell`` running the helper (protocol 2)."""

    def __init__(
        self,
        argv: list[str],
        *,
        pid: int = 4242,
        flags: int = 1,
        connect: str = "connected",
        hang_on_eof: bool = False,
        silent: frozenset[str] = frozenset(),
        shot_error: str | None = None,
    ) -> None:
        self.argv = argv
        self.pid = pid
        self.hang_on_eof = hang_on_eof
        self.silent = silent  # commands that never get a reply (timeouts)
        self.shot_error = shot_error  # every shot answers this error
        self.commands: list[str] = []
        self.returncode: int | None = None
        self.killed = False
        self._exited = threading.Event()
        self._wlock = threading.Lock()
        r, w = os.pipe()
        self.stdout = os.fdopen(r, "rb")
        self._out = os.fdopen(w, "wb", buffering=0)
        er, ew = os.pipe()
        self.stderr = os.fdopen(er, "rb")
        self._err = os.fdopen(ew, "wb", buffering=0)
        self.stdin = _Stdin(self)
        mode = "invisible" if flags == 2 else "full"
        self.emit(
            {
                "type": "hello",
                "version": "1.0.0",
                "protocol": 2,
                "pid": pid,
                "mode": mode,
                "flags": flags,
                "t_mono_ms": 1000.0,
                "display": {"w": 1080, "h": 2424, "rotation": 0},
            }
        )
        if connect:
            self.emit({"type": "status", "state": connect, "reason": "start"})

    # -- scripting --
    def emit(self, obj: dict | str) -> None:
        raw = obj if isinstance(obj, str) else json.dumps(obj)
        with self._wlock:
            if not self._out.closed:
                self._out.write(raw.encode() + b"\n")

    def die(self, rc: int = 1) -> None:
        if self.returncode is None:
            self.returncode = rc
        self._exited.set()
        with self._wlock:
            for f in (self._out, self._err):
                if not f.closed:
                    f.close()

    def on_command(self, line: str) -> None:
        self.commands.append(line)
        tok = line.split()
        rid = next((t[3:] for t in tok if t.startswith("id=")), None)
        kv = dict(t.split("=", 1) for t in tok[1:] if "=" in t)
        name = tok[0]
        if name in self.silent:
            return
        if name == "ping":
            self.emit(
                {"type": "pong", "id": rid, "t_mono_ms": 5000.0, "connected": True}
            )
        elif name == "node_at":
            self.emit(
                {
                    "type": "node_at",
                    "id": rid,
                    "x": int(tok[1]),
                    "y": int(tok[2]),
                    "cached": {"hit": {"text": "Old"}},
                    "live": {"target": {"text": "Btn", "rid": "a:id/b"}},
                }
            )
        elif name == "dump":
            self.emit(
                {
                    "type": "dump",
                    "id": rid,
                    "nodes": 3,
                    "max_nodes": int(kv["max_nodes"]),
                    "windows": [{"id": 1, "root": {"cls": "FrameLayout"}}],
                }
            )
        elif name == "windows":
            self.emit({"type": "windows", "id": rid, "windows": [{"id": 7}]})
        elif name == "shot" and self.shot_error:
            self.emit(
                {"type": "error", "id": rid, "cmd": "shot", "error": self.shot_error}
            )
        elif name == "shot":
            reply = {
                "type": "shot",
                "id": rid,
                "t_mono_ms": 1234.5,
                "w": 1080,
                "h": 2424,
                "hash": "0badf00d",
                "cap_ms": 14.2,
                "png_ms": 0.0 if "hash_only" in kv else 80.0,
            }
            if "path" in kv and "hash_only" not in kv:
                reply["path"] = kv["path"]
            self.emit(reply)
        else:
            self.emit({"type": "error", "id": rid, "error": f"unknown: {name}"})

    # -- Popen surface --
    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if not self._exited.wait(timeout):
            raise subprocess.TimeoutExpired(self.argv, timeout)
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.die(-9)

    terminate = kill


class FakeFetch:
    """``adb exec-out cat <png>``."""

    def __init__(self, argv: list[str], data: bytes) -> None:
        self.argv = argv
        self.data = data
        self.returncode: int | None = None

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        self.returncode = 0 if self.data else 1
        return self.data, b"" if self.data else b"No such file"

    def kill(self) -> None:
        pass


class FakePopen:
    """Popen factory: helper shells and screenshot fetches, all recorded."""

    def __init__(self, **helper_kw) -> None:
        self.helper_kw = helper_kw
        self.helpers: list[FakeHelper] = []
        self.fetches: list[FakeFetch] = []
        self.fetch_data = PNG
        self.order: list[str] = []
        self.next_kw: list[dict] = []  # per-spawn overrides, consumed in order

    def __call__(self, argv, **kw):
        if "exec-out" in argv:
            f = FakeFetch(argv, self.fetch_data)
            self.fetches.append(f)
            self.order.append("fetch " + argv[-1])
            return f
        opts = dict(self.helper_kw)
        if self.next_kw:
            opts.update(self.next_kw.pop(0))
        h = FakeHelper(argv, **opts)
        self.helpers.append(h)
        return h

    @property
    def current(self) -> FakeHelper:
        return self.helpers[-1]


class FakeAdb:
    """``Adb.send_adb_command`` stand-in: records (command, serial).

    Device files are ``files`` (path -> sha256); ``procs`` (pid -> ARGS) is
    what ``ps -A -o PID,ARGS`` lists, ``kill`` removes all but ``unkillable``.
    """

    def __init__(self, popen: FakePopen | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.files: dict[str, str] = {uihelper.REMOTE_JAR: uihelper.JAR_SHA256}
        self.push_result_sha = uihelper.JAR_SHA256
        self.procs: dict[int, str] = {}
        self.unkillable: set[int] = set()
        self.settings = {
            "accessibility_enabled": "0",
            "enabled_accessibility_services": "null",
        }
        self.popen = popen

    @property
    def device_jar_sha(self) -> str:
        return self.files.get(uihelper.REMOTE_JAR, "")

    @device_jar_sha.setter
    def device_jar_sha(self, sha: str) -> None:
        if sha:
            self.files[uihelper.REMOTE_JAR] = sha
        else:
            self.files.pop(uihelper.REMOTE_JAR, None)

    def __call__(self, command: str, serial: str | None = None, timeout: float = 30):
        self.calls.append((command, serial))
        if self.popen is not None:
            self.popen.order.append(command)
        if command.startswith("shell sha256sum "):
            path = command.split()[-1]
            sha = self.files.get(path)
            if not sha:
                return "", f"sha256sum: {path}: No such file"
            return f"{sha}  {path}\n", ""
        if command.startswith("push "):
            self.files[command.split()[-1]] = self.push_result_sha
            return "1 file pushed.\n", ""
        if command.startswith("shell rm -f "):
            self.files.pop(command.split()[-1], None)
            return "", ""
        if command.startswith("shell mv -f "):
            _, _, _, src, dst = command.split()
            if src in self.files:
                self.files[dst] = self.files.pop(src)
            return "", ""
        if command == "shell ps -A -o PID,ARGS":
            rows = ["  PID ARGS", "    1 init second_stage"]
            rows += [f"{pid:5d} {args}" for pid, args in sorted(self.procs.items())]
            return "\n".join(rows) + "\n", ""
        if command.startswith("shell kill "):
            for tok in command.split()[2:]:
                if tok.isdigit() and int(tok) not in self.unkillable:
                    self.procs.pop(int(tok), None)
            return "", ""
        if command.startswith("shell settings get secure "):
            return self.settings.get(command.rsplit(maxsplit=1)[-1], "null") + "\n", ""
        if command.startswith("shell settings put secure "):
            _, _, _, _, key, val = command.split()
            self.settings[key] = val
            return "", ""
        return "", ""

    def commands(self, prefix: str = "") -> list[str]:
        return [c for c, _ in self.calls if c.startswith(prefix)]


@pytest.fixture
def adb(monkeypatch):
    monkeypatch.setattr(Adb, "ADB_PATH", "/sdk/adb")
    fake = FakeAdb()
    monkeypatch.setattr(Adb, "send_adb_command", fake)
    return fake


class Recorder:
    def __init__(self) -> None:
        self.statuses: list[tuple[str, dict]] = []
        self.events: list[tuple[dict, float]] = []

    def on_status(self, state: str, info: dict) -> None:
        self.statuses.append((state, info))

    def on_event(self, line: dict, host_recv: float) -> None:
        self.events.append((line, host_recv))

    def states(self) -> list[str]:
        return [s for s, _ in self.statuses]


def make_helper(adb: FakeAdb, mode: Mode = Mode.FULL, **kw):
    popen = kw.pop("popen", None) or FakePopen(flags=2 if mode is Mode.INVISIBLE else 1)
    adb.popen = popen
    rec = Recorder()
    sleeps: list[float] = []
    h = UiHelper(
        SERIAL,
        mode,
        on_event=rec.on_event,
        on_status=rec.on_status,
        popen=popen,
        sleep=kw.pop("sleep", sleeps.append),
        clock=kw.pop("clock", lambda: 0.0),
        **kw,
    )
    return h, popen, rec, sleeps


# --------------------------------------------------------------- build / jar


def test_committed_jar_matches_jar_sha256():
    data = uihelper.jar_path().read_bytes()
    assert hashlib.sha256(data).hexdigest() == uihelper.JAR_SHA256
    assert len(uihelper.JAR_SHA256) == 64
    assert "<" not in uihelper.JAR_SHA256


def test_sources_match_source_sha256():
    # A Java change without a rebuild (and new constants) fails here.
    src = REPO / "tools" / "uihelper" / "src"
    assert sorted(p.name for p in src.rglob("*.java")) == [
        "Main.java",
        "Snapshots.java",
        "TouchWatch.java",
        "Tree.java",
        "Uia.java",
    ]
    assert uihelper.source_sha256(src) == uihelper.SOURCE_SHA256


def test_source_sha256_definition(tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "Y.java").write_bytes(b"class Y {}")
    (tmp_path / "A.java").write_bytes(b"class A {}")
    (tmp_path / "notes.txt").write_bytes(b"ignored")
    want = hashlib.sha256(b"A.java\0class A {}\0b/Y.java\0class Y {}\0").hexdigest()
    assert uihelper.source_sha256(tmp_path) == want


def test_jar_resolves_through_importlib_resources():
    res = resources.files("sandroid").joinpath("assets", "uihelper", "uihelper.jar")
    assert res.is_file()
    assert uihelper.jar_path() == Path(str(res))
    with zipfile.ZipFile(uihelper.jar_path()) as z:
        assert "classes.dex" in z.namelist()


def test_build_info():
    assert uihelper.build_info() == {
        "version": "1.0.0",
        "protocol": 2,
        "jar_sha256": uihelper.JAR_SHA256,
        "source_sha256": uihelper.SOURCE_SHA256,
    }


def test_java_constants_match_python():
    main = (REPO / "tools/uihelper/src/sandroid/uihelper/Main.java").read_text()
    assert f'VERSION = "{uihelper.HELPER_VERSION}"' in main
    assert f"PROTOCOL = {uihelper.PROTOCOL};" in main


# ---------------------------------------------------------------- ensure_jar


def test_ensure_jar_skips_when_device_hash_matches(adb):
    assert uihelper.ensure_jar(SERIAL) is True
    assert adb.commands() == [f"shell sha256sum {uihelper.REMOTE_JAR}"]
    assert all(s == SERIAL for _, s in adb.calls)


def test_ensure_jar_pushes_and_verifies_on_mismatch(adb):
    adb.device_jar_sha = ""  # absent on the device
    assert uihelper.ensure_jar(SERIAL) is True
    jar = uihelper.REMOTE_JAR
    tmp = uihelper._tmp_jar()
    assert tmp.startswith(jar + ".")
    assert tmp.endswith(".tmp")
    assert adb.commands() == [
        f"shell sha256sum {jar}",
        f"shell rm -f {tmp}",
        f"push {uihelper.quote_host_arg(str(uihelper.jar_path()))} {tmp}",
        f"shell sha256sum {tmp}",
        f"shell chmod 644 {tmp}",
        "shell ps -A -o PID,ARGS",
        f"shell mv -f {tmp} {jar}",
        f"shell sha256sum {jar}",
    ]
    assert adb.files == {jar: uihelper.JAR_SHA256}
    assert all(s == SERIAL for _, s in adb.calls)


def test_ensure_jar_fails_when_verify_mismatches(adb, caplog):
    adb.device_jar_sha = "0" * 64
    adb.push_result_sha = "1" * 64
    with caplog.at_level(logging.WARNING, logger="sandroid.core.uihelper"):
        assert uihelper.ensure_jar(SERIAL) is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert SERIAL in warnings[0].getMessage()
    assert not adb.commands("shell chmod")
    assert not adb.commands("shell mv")
    # the old jar is untouched, the half-written one removed
    assert adb.files == {uihelper.REMOTE_JAR: "0" * 64}
    assert all(s == SERIAL for _, s in adb.calls)


OLD_HELPER = "app_process / sandroid.uihelper.Main mode=full"


def test_upgrade_replaces_an_old_jar_atomically_and_stops_its_helper(adb, monkeypatch):
    """An old jar (main before this change) with its helper still running:
    the new jar goes to a temporary name, is verified, the old helper is
    stopped, then one rename swaps the jar -- never half-written.
    """
    jar = uihelper.REMOTE_JAR
    adb.device_jar_sha = "c" * 64
    adb.procs = {
        4242: OLD_HELPER,
        4300: f"sh -c CLASSPATH={jar} exec {OLD_HELPER}",  # not a helper
        4400: "com.android.chrome",
    }
    seen: list[str] = []
    real = adb.__call__

    def spy(command, serial=None, timeout=30):
        # at every step the jar is the old one or the new one, whole
        seen.append(adb.files.get(jar, "missing"))
        return real(command, serial, timeout)

    monkeypatch.setattr(Adb, "send_adb_command", spy)
    assert uihelper.helper_pids(SERIAL) == [4242]
    assert uihelper.ensure_jar(SERIAL) is True
    assert set(seen) <= {"c" * 64, uihelper.JAR_SHA256}
    cmds = [c for c, _ in adb.calls]
    assert cmds.index("shell kill 4242") < cmds.index(
        f"shell mv -f {uihelper._tmp_jar()} {jar}"
    )
    assert 4242 not in adb.procs
    assert 4400 in adb.procs
    assert 4300 in adb.procs
    assert adb.files == {jar: uihelper.JAR_SHA256}


def test_a_helper_that_ignores_kill_gets_kill_9(adb):
    adb.procs = {
        77: OLD_HELPER,
        78: "/system/bin/app_process64 / sandroid.uihelper.Main",
    }
    adb.unkillable = {77}
    assert uihelper.stop_stale_helpers(SERIAL, timeout=0.0) == [77, 78]
    assert "shell kill 77 78" in adb.commands()
    assert "shell kill -9 77" in adb.commands()


def test_no_helper_running_no_kill(adb):
    assert uihelper.stop_stale_helpers(SERIAL) == []
    assert not adb.commands("shell kill")


def test_a_current_jar_never_stops_a_running_helper(adb):
    adb.procs = {4242: OLD_HELPER}
    assert uihelper.ensure_jar(SERIAL) is True
    assert not adb.commands("shell kill")
    assert 4242 in adb.procs


def test_start_upgrades_an_old_jar_before_spawning(adb):
    adb.device_jar_sha = "c" * 64
    adb.procs = {4242: OLD_HELPER}
    popen = FakePopen()
    jar_at_spawn: list[str] = []

    def spawn(argv, **kw):
        jar_at_spawn.append(adb.device_jar_sha)
        jar_at_spawn.append("helper running" if 4242 in adb.procs else "stopped")
        return popen(argv, **kw)

    h, _popen, rec, _ = make_helper(adb, popen=popen)
    h._popen = spawn
    assert h.start() is True
    assert popen.order.index("shell kill 4242") < popen.order.index(
        f"shell mv -f {uihelper._tmp_jar()} {uihelper.REMOTE_JAR}"
    )
    # spawned once, with the new jar in place and the old helper gone
    assert jar_at_spawn == [uihelper.JAR_SHA256, "stopped"]
    h.stop()



# ------------------------------------------------------------ helper_command


@pytest.mark.parametrize("mode", [Mode.FULL, Mode.INVISIBLE])
def test_helper_command_shape(mode):
    c = uihelper.helper_command(mode)
    assert c.startswith(uihelper.ZYGOTE_ENV + "; ")
    assert "BOOTCLASSPATH" in c
    assert "/proc/$ZP/environ" in c
    assert f"CLASSPATH={uihelper.REMOTE_JAR} exec app_process / " in c
    assert c.endswith(f"sandroid.uihelper.Main mode={mode.value}")
    assert uihelper.helper_command("invisible", jar="/x.jar").endswith("mode=invisible")


def test_spawn_uses_serial_argv(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start() is True
    assert popen.helpers[0].argv == [
        "/sdk/adb",
        "-s",
        SERIAL,
        "shell",
        uihelper.helper_command(Mode.FULL),
    ]
    assert rec.states() == ["connected"]
    info = rec.statuses[0][1]
    assert info["pid"] == 4242
    assert info["flags"] == 1
    assert info["a11y_before"] == {
        "accessibility_enabled": "0",
        "enabled_accessibility_services": None,
    }
    assert h.alive
    assert h.hello["mode"] == "full"
    h.stop()


def test_start_fails_without_jar(adb):
    adb.device_jar_sha = ""
    adb.push_result_sha = "f" * 64
    h, popen, rec, _ = make_helper(adb)
    assert h.start() is False
    assert h.last_error == "jar"
    assert not popen.helpers
    assert rec.states() == []


def test_start_busy(adb):
    popen = FakePopen(connect="busy")
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start(timeout=2) is False
    assert rec.states() == ["busy"]
    assert h.last_error == "busy"
    assert popen.current.stdin.closed
    assert not h.alive


def test_start_timeout_returns_false(adb):
    popen = FakePopen(connect="")
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start(timeout=0.2) is False
    assert h.last_error == "timeout"
    assert rec.states() == []


# ----------------------------------------------------------- request / reply


def test_request_reply_by_id_and_unsolicited_events(adb, tmp_path):
    log = tmp_path / "raw" / "helper.jsonl"
    h, popen, rec, _ = make_helper(adb, raw_log=log)
    assert h.start()
    fake = popen.current
    fake.emit({"type": "ev", "ev": "CLICKED", "t_mono_ms": 1500})
    fake.emit({"type": "pong", "id": "nobody-asked"})
    r = h.request("ping")
    assert r["type"] == "pong"
    assert r["id"] == "r1"
    assert r["_host_recv"] >= r["_host_send"]
    assert fake.commands == ["ping id=r1"]
    assert wait_for(lambda: len(rec.events) >= 4)
    types = [e["type"] for e, _ in rec.events]
    assert types[:4] == ["hello", "status", "ev", "pong"]
    assert all(isinstance(t, float) for _, t in rec.events)
    h.stop()
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    rows = log.read_text().splitlines()
    t, raw = rows[0].split("\t", 1)
    assert float(t) > 0
    assert json.loads(raw)["type"] == "hello"
    assert any(json.loads(r.split("\t", 1)[1]).get("id") == "r1" for r in rows)
    assert json.loads(rows[-1].split("\t", 1)[1])["type"] == "bye"


def test_timeout_returns_none_without_raising(adb):
    popen = FakePopen(silent=frozenset({"windows", "ping"}))
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    assert h.windows(timeout=0.05) is None
    assert h.ping(timeout=0.05) is None
    assert h.request("windows", timeout=0.05) is None
    assert h._waiters == {}
    h.stop()


def test_malformed_lines_do_not_kill_reader(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    fake = popen.current
    for junk in ("not json", "[1, 2]", "\x00\x01", '{"type": "ev", "id": ', "42"):
        fake.emit(junk)
    fake._out.write(b"\xff\xfe broken utf8\n")
    assert h.ping()["connected"] is True
    assert h.alive
    h.stop()


def test_callback_exception_does_not_kill_reader(adb):
    h, popen, rec, _ = make_helper(adb)

    def boom(line, t):
        raise RuntimeError("callback bug")

    h._on_event = boom
    assert h.start()
    popen.current.emit({"type": "ev", "ev": "CLICKED"})
    assert h.ping() is not None
    h.stop()


def test_queries_parse_replies(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    fake = popen.current
    r = h.node_at(5, 6, t_mono_ms=1234.56)
    assert fake.commands[-1].startswith("node_at 5 6 both t=1234.6 id=")
    assert r["live"]["target"]["rid"] == "a:id/b"
    assert r["cached"]["hit"]["text"]
    r = h.node_at(1, 2)
    assert fake.commands[-1].startswith("node_at 1 2 both id=")
    d = h.dump(max_nodes=99)
    assert d["max_nodes"] == 99
    assert d["windows"][0]["root"]["cls"] == "FrameLayout"
    assert h.windows() == [{"id": 7}]
    p = h.ping()
    assert p["t_mono_ms"] == 5000.0
    assert p["connected"] is True
    assert p["rtt_ms"] >= 0
    assert p["host_mid"] > 1e9
    s = h.shot(hash_only=True)
    assert s == uihelper.ShotResult(1234.5, 1080, 2424, "0badf00d", 14.2, None, None)
    assert fake.commands[-1].startswith("shot hash_only=1 id=")
    assert not popen.fetches
    h.stop()


def test_error_reply_returns_none(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    popen.current.on_command = lambda line: popen.current.emit(
        {"type": "error", "id": line.split("id=")[1], "error": "not_connected"}
    )
    assert h.node_at(1, 1) is None
    assert h.shot() is None
    h.stop()


def test_invisible_mode_short_circuits_a11y_queries(adb):
    h, popen, rec, _ = make_helper(adb, Mode.INVISIBLE)
    assert h.start()
    fake = popen.current
    assert fake.argv[-1].endswith("mode=invisible")
    assert h.node_at(1, 2) is None
    assert h.dump() is None
    assert h.windows() is None
    assert fake.commands == []  # no round trip
    assert h.shot(hash_only=True).hash == "0badf00d"
    # INVISIBLE never reads or touches the a11y settings.
    assert not adb.commands("shell settings")
    assert rec.statuses[0][1]["flags"] == 2
    h.stop()
    assert not adb.commands("shell settings")


def test_shot_fetches_with_exec_out_cat_then_rm(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    s1 = h.shot()
    s2 = h.shot()
    assert s1.png == PNG
    assert s1.error is None
    assert s1.w == 1080
    assert s1.remote_path.startswith(uihelper.REMOTE_SHOT_DIR + "/")
    assert s1.remote_path.endswith(".png")
    assert s1.remote_path != s2.remote_path
    f = popen.fetches[0]
    assert f.argv == ["/sdk/adb", "-s", SERIAL, "exec-out", "cat", s1.remote_path]
    cmds = popen.order
    mk = f"shell mkdir -p {uihelper.REMOTE_SHOT_DIR}"
    assert cmds.count(mk) == 1  # once
    i = cmds.index(f"fetch {s1.remote_path}")
    assert cmds[i + 1] == f"shell rm -f {s1.remote_path}"
    assert cmds.index(mk) < i
    assert any(
        c.startswith(f"shot path={s1.remote_path} id=") for c in popen.current.commands
    )
    assert all(s == SERIAL for _, s in adb.calls)
    h.stop()


def test_shot_fetch_failure_keeps_capture(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    popen.fetch_data = b""
    s = h.shot()
    assert s.png is None
    assert "fetch failed" in s.error
    assert s.hash == "0badf00d"
    assert adb.commands(f"shell rm -f {s.remote_path}")
    h.stop()


# ---------------------------------------------------------- restart and stop


def test_eof_lost_then_restarted(adb):
    h, popen, rec, sleeps = make_helper(adb)
    assert h.start()
    popen.current.die(137)
    assert wait_for(lambda: rec.states() == ["connected", "lost", "restarted"])
    assert sleeps == [1.0]
    assert rec.statuses[1][1]["rc"] == 137
    assert len(popen.helpers) == 2
    assert h.alive
    # the restart re-checked the jar (a snapshot load may have wiped it)
    assert len(adb.commands("shell sha256sum")) == 2
    assert h.ping() is not None
    h.stop()
    assert rec.states()[-1] == "stopped"


def test_no_restart_once_a_quit_suppressed_it(adb):
    """F1: a helper killed during quit is neither "lost · restarting" nor
    restarted; the quit's stop() still reports "stopped".
    """
    h, popen, rec, sleeps = make_helper(adb)
    assert h.start()
    h.suppress_restarts()
    reader = h._gen.reader
    popen.current.die(137)
    reader.join(10.0)  # the reader handled the death (and is done)
    assert not reader.is_alive()
    assert h._supervisor is None  # nothing to restart it
    assert rec.states() == ["connected"]
    assert len(popen.helpers) == 1
    assert sleeps == []
    h.stop()
    assert rec.states() == ["connected", "stopped"]


def test_pending_request_fails_fast_on_death(adb):
    popen = FakePopen(silent=frozenset({"dump"}))
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    res: dict = {}
    t = threading.Thread(target=lambda: res.setdefault("dump", h.dump(timeout=60)))
    t.start()
    assert wait_for(lambda: any(c.startswith("dump") for c in popen.current.commands))
    popen.current.die()
    t.join(10.0)
    assert not t.is_alive()  # woken by the death, not by its 60 s timeout
    assert res["dump"] is None
    h.stop()


def test_five_deaths_go_down(adb):
    h, popen, rec, sleeps = make_helper(adb)
    assert h.start()
    for n in range(1, 5):
        popen.current.die()
        assert wait_for(lambda n=n: rec.states().count("restarted") == n)
    popen.current.die()
    assert wait_for(lambda: rec.states()[-1:] == ["down"])
    assert rec.states() == ["connected"] + ["lost", "restarted"] * 4 + ["lost", "down"]
    assert sleeps == [1.0, 2.0, 4.0, 8.0]
    assert len(popen.helpers) == 5
    assert not h.alive
    h._supervisor.join(10.0)  # the only spawner is done
    assert not h._supervisor.is_alive()
    assert len(popen.helpers) == 5  # no more restarts
    h.stop()
    assert rec.states()[-1] == "stopped"


def test_failed_restarts_count_as_deaths(adb):
    h, popen, rec, sleeps = make_helper(adb)
    assert h.start()
    popen.next_kw = [{"connect": "busy"}] * 10  # every restart finds it busy
    popen.current.die()
    assert wait_for(lambda: rec.states()[-1:] == ["down"])
    assert rec.states() == ["connected", "lost", "down"]
    assert sleeps == [1.0, 2.0, 4.0, 8.0]
    h.stop()


def test_stable_run_resets_backoff(adb):
    now = [0.0]
    h, popen, rec, sleeps = make_helper(adb, clock=lambda: now[0])
    assert h.start()
    for n in range(1, 8):
        now[0] += 61.0  # each run lasted longer than the death window
        popen.current.die()
        assert wait_for(lambda n=n: rec.states().count("restarted") == n)
    assert sleeps == [1.0] * 7
    assert "down" not in rec.states()
    h.stop()


def test_backoff_grows_and_caps_at_ten(adb):
    now = [0.0]
    h, popen, rec, sleeps = make_helper(adb, clock=lambda: now[0])
    assert h.start()
    for n in range(1, 7):
        now[0] += 20.0  # deaths spread out: never 5 inside 60 s
        popen.current.die()
        assert wait_for(lambda n=n: rec.states().count("restarted") == n)
    assert sleeps == [1.0, 2.0, 4.0, 8.0, 10.0, 10.0]
    h.stop()


# ----------------------------------------- the system server restarted under it

#: Every shot's answer once the system server restarted under the helper (a
#: real session, after the CA injection's Zygote restart).
DEAD_SYSTEM = "DeadSystemRuntimeException: android.os.DeadSystemException"


def _reconnect_in_place(fake: FakeHelper) -> None:
    """The helper's watchdog saw UiAutomation drop and reconnected it."""
    fake.emit({"type": "status", "state": "lost", "reason": "watchdog"})
    fake.emit({"type": "status", "state": "connected", "reason": "reconnect"})


@pytest.mark.parametrize("mode", [Mode.FULL, Mode.INVISIBLE])
def test_a_dead_system_shot_error_replaces_the_helper_process(adb, mode):
    """A Zygote restart killed the system server under the helper. Node
    queries worked again after the in-place reconnect, but every shot failed
    with DeadSystemException for the rest of the session (26 before-tap
    shots in a row). The first such error now replaces the process.
    """
    popen = FakePopen(flags=2 if mode is Mode.INVISIBLE else 1)
    popen.next_kw = [{"shot_error": DEAD_SYSTEM}]
    h, popen, rec, sleeps = make_helper(adb, mode, popen=popen)
    assert h.start()
    stale = popen.current
    assert h.shot() is None
    assert wait_for(lambda: rec.states() == ["connected", "lost", "restarted"])
    assert rec.statuses[1][1]["reason"] == "system_restart"
    assert stale.stdin.closed  # it exited on EOF
    assert not stale.killed
    assert len(popen.helpers) == 2
    assert sleeps == [1.0]
    assert h.shot().png == PNG
    h.stop()


def test_a_reconnect_in_place_probes_and_replaces_a_stale_process(adb):
    """The in-place reconnect is the first sign: a hash-only probe finds the
    stale process before a real shot can fail.
    """
    popen = FakePopen()
    popen.next_kw = [{"shot_error": DEAD_SYSTEM}]
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    stale = popen.current
    _reconnect_in_place(stale)
    assert wait_for(lambda: rec.states() == ["connected", "lost", "restarted"])
    assert [c.split(" id=")[0] for c in stale.commands] == ["shot hash_only=1"]
    assert rec.statuses[1][1]["reason"] == "system_restart"
    assert h.shot().png == PNG
    h.stop()


def test_a_reconnect_in_place_with_a_live_system_keeps_the_process(adb):
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    fake = popen.current
    _reconnect_in_place(fake)
    assert wait_for(
        lambda: any(c.startswith("shot hash_only=1") for c in fake.commands)
    )
    assert h.ping() is not None  # replies are read in order: the probe's first
    assert rec.states() == ["connected"]
    assert len(popen.helpers) == 1
    h.stop()


def test_a_refused_reconnect_in_place_replaces_the_process(adb):
    """Dev3 under load: the Zygote restart took 37 s, the watchdog's connect
    timed out but registered anyway, and every later reconnect was "already
    registered" (busy): all requests "not connected" for good.
    """
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    stale = popen.current
    stale.emit({"type": "status", "state": "lost", "reason": "watchdog"})
    stale.emit({"type": "status", "state": "error", "reason": "reconnect",
                "detail": "RuntimeException: TimeoutException"})  # fmt: skip
    stale.emit({"type": "status", "state": "busy", "reason": "reconnect",
                "detail": "IllegalStateException: already registered"})  # fmt: skip
    assert wait_for(lambda: rec.states() == ["connected", "lost", "restarted"])
    assert rec.statuses[1][1]["reason"] == "reconnect_busy"
    assert stale.stdin.closed
    assert h.node_at(1, 2) is not None
    h.stop()


def test_no_replacement_once_a_quit_suppressed_restarts(adb):
    popen = FakePopen()
    popen.next_kw = [{"shot_error": DEAD_SYSTEM}]
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    h.suppress_restarts()
    assert h.shot() is None
    assert h.ping() is not None  # the error was handled: nothing replaced it
    assert not popen.current.stdin.closed
    assert len(popen.helpers) == 1
    h.stop()
    assert rec.states() == ["connected", "stopped"]


def test_stop_during_backoff_does_not_restart(adb):
    gate = threading.Event()
    h, popen, rec, _ = make_helper(adb, sleep=lambda s: gate.wait(2))
    assert h.start()
    popen.current.die()
    assert wait_for(lambda: "lost" in rec.states())
    stopper = threading.Thread(target=h.stop)
    stopper.start()
    assert wait_for(lambda: h._stopping)
    gate.set()
    stopper.join(3)
    assert "restarted" not in rec.states()
    assert rec.states()[-1] == "stopped"
    assert len(popen.helpers) == 1


def test_stop_kills_pid_when_helper_hangs(adb):
    popen = FakePopen(hang_on_eof=True, pid=777)
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    h.stop(timeout=0.1)
    assert adb.commands("shell kill 777")
    assert popen.current.killed
    assert ("shell kill 777", SERIAL) in adb.calls
    assert rec.states() == ["connected", "stopped"]


@pytest.mark.parametrize(
    ("before", "after", "restored"),
    [
        ("0", "1", True),
        ("null", "1", True),
        ("1", "1", False),  # was on before (a real a11y service): leave it
        ("0", "0", False),  # the system already reset it
    ],
)
def test_stop_restores_accessibility_enabled(adb, before, after, restored):
    adb.settings["accessibility_enabled"] = before
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    adb.settings["accessibility_enabled"] = after
    h.stop()
    puts = adb.commands("shell settings put")
    if restored:
        assert puts == ["shell settings put secure accessibility_enabled 0"]
    else:
        assert puts == []
    assert rec.statuses[-1][0] == "stopped"
    assert rec.statuses[-1][1]["a11y_restored"] is restored
    assert all(s == SERIAL for _, s in adb.calls)


def test_stop_before_start_is_noop(adb):
    h, popen, rec, _ = make_helper(adb)
    h.stop()
    assert rec.states() == []
    assert adb.calls == []


def test_requires_serial():
    with pytest.raises(ValueError):
        UiHelper("")


# ------------------------------------------- lifecycle races (review 2 H1/M7/M8)


class _A11yPopen(FakePopen):
    """Each helper spawn flips accessibility_enabled to 1 (FULL connect)."""

    def __init__(self, adb: FakeAdb, gate: threading.Event | None = None, **kw) -> None:
        super().__init__(**kw)
        self.adb = adb
        self.gate = gate  # adb shell comes up only once it is set
        self.spawning = threading.Event()

    def __call__(self, argv, **kw):
        if "exec-out" not in argv:
            self.spawning.set()
            if self.gate is not None:
                self.gate.wait(10.0)
            self.adb.settings["accessibility_enabled"] = "1"
        return super().__call__(argv, **kw)


def test_stop_during_start_kills_inflight_helper_and_restores_a11y(adb):
    gate = threading.Event()
    popen = _A11yPopen(adb, gate=gate)
    h, popen, rec, _ = make_helper(adb, popen=popen)
    res = {}
    t = threading.Thread(target=lambda: res.setdefault("ok", h.start()))
    t.start()
    assert popen.spawning.wait(10.0)  # adb shell is coming up ...
    # ... when the app quits while tracking is starting
    stopper = threading.Thread(target=h.stop)
    stopper.start()
    assert wait_for(lambda: h._stopping)
    gate.set()  # the helper process appears after the stop
    stopper.join(10.0)
    t.join(10.0)
    assert not stopper.is_alive()
    assert res["ok"] is False
    assert h.last_error == "cancelled"
    helper = popen.helpers[0]
    assert helper.stdin.closed
    assert helper.returncode is not None
    assert adb.settings["accessibility_enabled"] == "0"
    assert rec.states() == ["stopped"]
    assert rec.statuses[-1][1]["a11y_restored"] is True
    assert not h.alive
    h.stop()  # idempotent
    assert rec.states() == ["stopped"]


def test_stop_while_start_waits_for_connect_returns_promptly(adb):
    popen = _A11yPopen(adb, connect="")  # never says connected
    h, popen, rec, _ = make_helper(adb, popen=popen)
    res = {}
    t = threading.Thread(target=lambda: res.setdefault("ok", h.start(timeout=20)))
    t.start()
    assert wait_for(lambda: popen.helpers)
    h.stop(timeout=1)
    t.join(10.0)
    assert not t.is_alive()  # cancelled, not ended by its 20 s timeout
    assert res["ok"] is False
    assert popen.helpers[0].returncode is not None
    assert adb.settings["accessibility_enabled"] == "0"
    assert rec.states() == ["stopped"]


def test_start_during_backoff_has_one_spawner(adb):
    gate = threading.Event()
    h, popen, rec, _ = make_helper(adb, sleep=lambda s: gate.wait(5))
    assert h.start()
    popen.current.die()
    assert wait_for(lambda: "lost" in rec.states())
    assert h.start() is True  # the caller reacts to "lost"
    gen2 = popen.helpers[-1]
    sup = h._supervisor
    gate.set()  # the supervisor's back-off ends: it must not spawn again
    sup.join(10.0)
    assert not sup.is_alive()
    assert len(popen.helpers) == 2
    assert h._gen.proc is gen2
    assert "restarted" not in rec.states()
    assert h.alive
    h.stop()
    assert gen2.stdin.closed
    assert gen2.returncode is not None
    assert rec.states()[-1] == "stopped"


def test_restarts_that_keep_timing_out_go_down(adb):
    now = [0.0]

    def sleep(s):
        now[0] += s

    h, popen, rec, _ = make_helper(adb, sleep=sleep, clock=lambda: now[0])
    assert h.start()
    n = [0]

    def spawn(timeout, token):  # every restart hangs until its connect timeout
        n[0] += 1
        now[0] += timeout
        return "timeout"

    h._spawn = spawn
    popen.current.die()
    assert wait_for(lambda: rec.states()[-1:] == ["down"])
    assert n[0] == uihelper.MAX_FAILED_RESTARTS
    assert rec.statuses[-1][1]["failed_restarts"] == uihelper.MAX_FAILED_RESTARTS
    h.stop()
    assert rec.states()[-1] == "stopped"


# ------------------------------------------------------- buffered reading (M9)


def test_buffered_wraps_raw_pipe_only():
    r, w = os.pipe()
    raw = os.fdopen(r, "rb", buffering=0)
    try:
        assert isinstance(uihelper._buffered(raw), io.BufferedReader)
        buf = os.fdopen(w, "wb")
        assert uihelper._buffered(buf) is buf
        buf.close()
    finally:
        raw.close()


@pytest.mark.perf
def test_big_reply_on_unbuffered_pipe_is_fast(adb):
    big = "x" * 3_000_000

    class RawHelper(FakeHelper):
        def __init__(self, argv, **kw):
            super().__init__(argv, **kw)
            # what Popen(bufsize=0) hands the reader: a raw FileIO
            self.stdout = os.fdopen(os.dup(self.stdout.fileno()), "rb", buffering=0)

        def on_command(self, line):
            rid = line.split("id=")[1]
            self.emit({"type": "dump", "id": rid, "windows": [], "blob": big})

    class RawPopen(FakePopen):
        def __call__(self, argv, **kw):
            h = RawHelper(argv, **self.helper_kw)
            self.helpers.append(h)
            return h

    h, popen, rec, _ = make_helper(adb, popen=RawPopen())
    assert h.start()
    t0 = time.monotonic()
    d = h.dump(timeout=20)
    elapsed = time.monotonic() - t0
    assert d is not None
    assert len(d["blob"]) == len(big)
    assert elapsed < 1.5  # byte-by-byte readline took ~1.6 s for 3 MB
    h.stop()


# ---------------------------------------------------- a11y restore (R1#8, L18)


@pytest.mark.parametrize("connect", ["busy", ""])
def test_failed_start_restores_a11y(adb, connect):
    popen = _A11yPopen(adb, connect=connect)
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start(timeout=0.2) is False
    assert adb.settings["accessibility_enabled"] == "0"
    assert adb.commands("shell settings put") == [
        "shell settings put secure accessibility_enabled 0"
    ]
    assert popen.helpers[0].returncode is not None
    assert not h.alive
    h.stop()  # nothing left to stop
    assert "stopped" not in rec.states()


def test_failed_before_read_is_not_treated_as_unset(adb):
    real = adb.__call__

    def flaky(command, serial=None, timeout=30):
        if command == "shell settings get secure accessibility_enabled" and not (
            adb.settings.get("_read_once")
        ):
            adb.settings["_read_once"] = "1"
            adb.calls.append((command, serial))
            return "", "error: closed"
        return real(command, serial, timeout)

    Adb.send_adb_command = flaky
    adb.settings["accessibility_enabled"] = "1"  # e.g. TalkBack was on
    h, popen, rec, _ = make_helper(adb)
    assert h.start()
    assert "accessibility_enabled" not in h.a11y_before
    h.stop()
    assert adb.commands("shell settings put") == []
    assert adb.settings["accessibility_enabled"] == "1"
    assert rec.statuses[-1][1]["a11y_restored"] is False


def test_stop_kills_supervisor_spawn_before_restoring_a11y(adb):
    popen = _A11yPopen(adb)
    h, popen, rec, _ = make_helper(adb, popen=popen)
    assert h.start()
    popen.next_kw = [{"connect": ""}]  # the restart hangs waiting for connect
    popen.current.die()
    assert wait_for(lambda: len(popen.helpers) == 2)
    inflight = popen.helpers[1]
    seen = {}
    real = Adb.send_adb_command

    def spy(command, serial=None, timeout=30):
        if command.startswith("shell settings put"):
            seen["helper_rc_at_restore"] = inflight.returncode
        return real(command, serial, timeout)

    Adb.send_adb_command = spy
    stopper = threading.Thread(target=h.stop, kwargs={"timeout": 1})
    stopper.start()
    stopper.join(10.0)
    assert not stopper.is_alive()  # not the 20 s restart connect timeout
    assert seen["helper_rc_at_restore"] is not None
    assert inflight.stdin.closed
    assert "restarted" not in rec.states()
    assert rec.states()[-1] == "stopped"
    assert adb.settings["accessibility_enabled"] == "0"


def test_stop_from_connected_callback_does_not_wait_for_start(adb):
    h, popen, rec, _ = make_helper(adb)

    def on_status(state, info):
        rec.on_status(state, info)
        if state == "connected":
            h.stop(timeout=30)  # waiting for start() would take 35 s

    h._on_status = on_status
    res: dict = {}
    t = threading.Thread(target=lambda: res.setdefault("ok", h.start()))
    t.start()
    t.join(10.0)
    assert not t.is_alive()
    assert res["ok"] is True
    assert rec.states() == ["connected", "stopped"]
