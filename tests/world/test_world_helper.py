"""World helper: the shipped jar, its protocol client and the pinned device wrapper."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from sandroid.world import helper
from sandroid.world.helper import Device, HelperClient, HelperError, ShellResult

REPO = Path(__file__).resolve().parents[2]
SERIAL = "emulator-5999"


def test_committed_jar_matches_jar_sha256() -> None:
    data = helper.jar_path().read_bytes()
    assert data[:2] == b"PK"
    assert hashlib.sha256(data).hexdigest() == helper.JAR_SHA256


def test_sources_match_source_sha256() -> None:
    src = REPO / "tools" / "worldhelper" / "src"
    assert helper.source_sha256(src) == helper.SOURCE_SHA256


def test_java_constants_match_python() -> None:
    main = (REPO / "tools/worldhelper/src/sandroid/worldhelper/Main.java").read_text()
    assert f'VERSION = "{helper.HELPER_VERSION}"' in main
    assert f"PROTOCOL = {helper.PROTOCOL};" in main
    assert f"package {helper.MAIN_CLASS.rsplit('.', 1)[0]};" in main


def test_build_script_writes_the_packaged_jar() -> None:
    build = (REPO / "tools/worldhelper/build.sh").read_text()
    assert "src/sandroid/assets/worldhelper/worldhelper.jar" in build
    assert "--release 8" in build


def test_helper_command_imports_zygote_env_and_execs() -> None:
    cmd = helper.helper_command()
    assert cmd.startswith(helper.ZYGOTE_ENV)
    assert cmd.endswith(
        f"CLASSPATH={helper.REMOTE_JAR} exec app_process / {helper.MAIN_CLASS}"
    )


# ------------------------------------------------------------------ Device


def test_device_pins_the_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"ok\n", b"")

    monkeypatch.setattr(
        helper.Adb, "base_argv", lambda serial=None: ["adb", "-s", serial]
    )
    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    dev = Device(SERIAL)
    assert dev.shell("id -u").out == "ok\n"
    dev.push([Path("/tmp/a"), "/tmp/b"], "/sdcard/")
    dev.shell("content query", zygote=True)
    assert seen[0] == ["adb", "-s", SERIAL, "shell", "id -u"]
    assert seen[1] == ["adb", "-s", SERIAL, "push", "/tmp/a", "/tmp/b", "/sdcard/"]
    assert seen[2][4].startswith(helper.ZYGOTE_ENV)
    with pytest.raises(ValueError):
        Device("")


def test_device_reports_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    monkeypatch.setattr(helper.subprocess, "run", slow)
    res = Device(SERIAL, adb_argv=["adb", "-s", SERIAL]).shell("sleep 99", timeout=1)
    assert res.rc == 124
    assert not res.ok


class _JarDevice:
    def __init__(self, remote: dict[str, str]) -> None:
        self.serial = SERIAL
        self.remote = remote
        self.calls: list[str] = []
        self.push_sha = helper.JAR_SHA256

    def shell(self, script: str, **kw) -> ShellResult:
        self.calls.append(script)
        if script.startswith("sha256sum"):
            path = script.split()[1]
            sha = self.remote.get(path)
            return ShellResult(0, f"{sha}  {path}\n" if sha else "", "")
        if "mv -f" in script:
            tmp = script.split("mv -f ")[1].split()[0]
            self.remote[helper.REMOTE_JAR] = self.remote.pop(tmp)
        return ShellResult(0, "", "")

    def push(self, sources, remote, **kw) -> ShellResult:
        self.calls.append(f"push {remote}")
        self.remote[remote] = self.push_sha
        return ShellResult(0, "1 file pushed", "")


def test_ensure_jar_skips_when_current() -> None:
    dev = _JarDevice({helper.REMOTE_JAR: helper.JAR_SHA256})
    helper.ensure_jar(dev)
    assert dev.calls == [f"sha256sum {helper.REMOTE_JAR} 2>/dev/null"]


def test_ensure_jar_pushes_verifies_and_renames() -> None:
    dev = _JarDevice({helper.REMOTE_JAR: "old"})
    helper.ensure_jar(dev)
    assert dev.remote == {helper.REMOTE_JAR: helper.JAR_SHA256}
    assert any(c.startswith("push ") and c.endswith(".tmp") for c in dev.calls)


def test_ensure_jar_refuses_a_bad_push() -> None:
    dev = _JarDevice({})
    dev.push_sha = "f" * 64
    with pytest.raises(HelperError, match="verification"):
        helper.ensure_jar(dev)
    assert helper.REMOTE_JAR not in dev.remote


# ------------------------------------------------------------ the protocol

FAKE_HELPER = r"""
import json, sys
print("WARNING: linker noise", flush=True)
print(json.dumps({"type": "hello", "protocol": int(sys.argv[1]), "version": "1.0.0"}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    cmd = req["cmd"]
    if cmd == "quit":
        print(json.dumps({"id": req["id"], "ok": True}), flush=True)
        break
    if cmd == "boom":
        print(json.dumps({"id": req["id"], "ok": False, "error": "java.lang.X: no"}), flush=True)
        continue
    if cmd == "die":
        print("fatal: dying", file=sys.stderr, flush=True)
        sys.exit(3)
    if cmd == "hang":
        continue
    print(json.dumps({"id": 999, "ok": True}), flush=True)
    print(json.dumps({"id": req["id"], "ok": True, "echo": req, "uni": "Grüße"},
                     ensure_ascii=False), flush=True)
"""


def _fake(protocol: int = helper.PROTOCOL) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", FAKE_HELPER, str(protocol)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def test_client_round_trip_and_errors() -> None:
    client = HelperClient(_fake())
    hello = client.start(timeout=20)
    assert hello["protocol"] == helper.PROTOCOL
    reply = client.request("contacts", items=[{"raw": {"starred": 1}}], timeout=20)
    assert reply["echo"]["items"] == [{"raw": {"starred": 1}}]
    assert reply["uni"] == "Grüße"
    with pytest.raises(HelperError, match="java.lang.X"):
        client.request("boom", timeout=20)
    with pytest.raises(HelperError, match="timed out"):
        client.request("hang", timeout=0.3)
    with pytest.raises(HelperError, match="exited during die"):
        client.request("die", timeout=20)
    client.close()


def test_client_rejects_another_protocol() -> None:
    client = HelperClient(_fake(protocol=99))
    with pytest.raises(HelperError, match="protocol 99"):
        client.start(timeout=20)


def test_client_close_quits_the_process() -> None:
    proc = _fake()
    with HelperClient(proc) as client:
        client.start(timeout=20)
    assert proc.wait(timeout=10) == 0


def test_chunked() -> None:
    assert helper.chunked(list(range(5)), 2) == [[0, 1], [2, 3], [4]]
    assert helper.chunked([], 3) == []
