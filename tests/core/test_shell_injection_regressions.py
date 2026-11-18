"""Regression tests: untrusted values must never run commands on the HOST.

``Adb.send_adb_command`` runs its command line through the real host shell
(``shell=True``). These tests point ``Adb.ADB_PATH`` at a fake adb script in
``tmp_path`` (not named ``adb``, so the conftest guard lets it run) that only
records its argv, then feed injection payloads (``$(touch MARK)``,
``;touch MARK;#`` ...) through the real sinks. A created marker file means the
host shell executed the payload. Everything stays inside ``tmp_path``.
"""

from __future__ import annotations

import os
import shlex
import stat

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.core import adb_utils
from sandroid.core.adb import Adb


@pytest.fixture
def fake_adb(tmp_path, monkeypatch):
    """Real host shell + fake adb that logs one argv word per line."""
    log = tmp_path / "argv.log"
    script = tmp_path / "fakeadb"
    script.write_text(
        "#!/bin/sh\n"
        f'for a in "$@"; do printf "%s\\n" "$a"; done >> {shlex.quote(str(log))}\n'
        f"echo '--' >> {shlex.quote(str(log))}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(Adb, "ADB_PATH", str(script))
    monkeypatch.setattr(Adb, "_target_device", None)
    monkeypatch.chdir(tmp_path)

    class _Fake:
        marker = tmp_path / "MARK"
        payload_sub = f"$(touch {tmp_path / 'MARK'})"
        payload_semi = f";touch {tmp_path / 'MARK'};#"

        @staticmethod
        def calls() -> list[list[str]]:
            if not log.exists():
                return []
            out, cur = [], []
            for line in log.read_text().splitlines():
                if line == "--":
                    out.append(cur)
                    cur = []
                else:
                    cur.append(line)
            return out

    return _Fake


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX host shell only")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_device_shell_arg_survives_both_shells():
    value = "/data/a b/$(id)'x\"`y`"
    host_words = shlex.split("shell cat " + adb_utils.device_shell_arg(value))
    assert host_words[:2] == ["shell", "cat"]
    assert shlex.split(host_words[2]) == [value]


def test_device_glob_arg_keeps_wildcards_but_quotes_literals():
    word = shlex.split(adb_utils.device_glob_arg("/data/a b/$(id)*.db"))[0]
    # The device shell sees quoted literals with a bare ``*``.
    assert word == "'/data/a b/$(id)'*.db"
    assert shlex.split(adb_utils.device_glob_arg("/data/plain/*"))[0] == (
        "/data/plain/*"
    )


@pytest.mark.parametrize("name", ["com.example.app", "a.b", "org.x_y.Z9"])
def test_validate_package_name_accepts(name):
    assert adb_utils.validate_package_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "app", "a.b;id", "a.b c", "com.$(id).x", "1a.b", None, 5]
)
def test_validate_package_name_rejects(name):
    with pytest.raises(ValueError):
        adb_utils.validate_package_name(name)


@pytest.mark.parametrize("name", ["tmp", b"tmp", "sandroid_x_20250101", "a.b-c"])
def test_validate_snapshot_name_accepts(name):
    assert adb_utils.validate_snapshot_name(name) in ("tmp", name)


@pytest.mark.parametrize(
    "name", ["", "..", "-x", ".hidden", "a b", "x;id", "a/b", "x\nkill", b"\xff"]
)
def test_validate_snapshot_name_rejects(name):
    with pytest.raises(ValueError):
        adb_utils.validate_snapshot_name(name)


@pytest.mark.parametrize("pid", [1, "42", " 7 "])
def test_validate_pid_accepts(pid):
    assert adb_utils.validate_pid(pid) == int(str(pid).strip())


@pytest.mark.parametrize("pid", [0, -1, "1;id", True, 1.5, None, "", "١"])
def test_validate_pid_rejects(pid):
    with pytest.raises(ValueError):
        adb_utils.validate_pid(pid)


# ---------------------------------------------------------------------------
# C1: device filenames (watchlist stat, wildcard expansion)
# ---------------------------------------------------------------------------


def test_watchlist_device_hash_command_does_not_run_device_filenames(
    fake_adb, monkeypatch
):
    """The pre-pull ``stat`` + ``sha256sum`` call quotes every path for the
    device shell and the whole command once more for the host shell.
    """
    from sandroid.tui.widgets.watchlist_view import WatchlistView

    monkeypatch.setattr(WatchlistView, "_adb", staticmethod(lambda: Adb))
    evil = f"/data/data/com.evil/files/{fake_adb.payload_sub}"
    WatchlistView._device_facts(["/data/a b.txt", evil])

    assert not fake_adb.marker.exists()
    (argv,) = fake_adb.calls()
    assert argv[0] == "shell"
    assert len(argv) == 2  # one host word: the device command line
    words = shlex.split(argv[1])
    assert words[:3] == ["stat", "-c", "%Y %s %n"]
    # The device shell sees the paths as literal words (twice: stat, sha256sum).
    assert words.count("/data/a b.txt") == 2
    assert words.count(evil) == 2
    assert "sha256sum" in words


def test_spotlight_wildcard_listing_is_host_safe(fake_adb):
    from sandroid.services.forensic_service import ForensicService

    ForensicService().add_spotlight_file(
        f"/data/local/tmp/x{fake_adb.payload_semi}/*", adb=Adb
    )
    ForensicService().add_spotlight_file(
        f"/data/local/tmp/{fake_adb.payload_sub}*", adb=Adb
    )
    assert not fake_adb.marker.exists()
    find_call, ls_call = fake_adb.calls()
    assert find_call[:2] == ["shell", "find"]
    assert find_call[-2:] == ["-type", "f"]
    assert ls_call[:3] == ["shell", "ls", "-1A"]


# ---------------------------------------------------------------------------
# C2: core sinks reachable from READ_ONLY AI tools
# ---------------------------------------------------------------------------


def test_core_sinks_quote_package_and_pid(fake_adb):
    Adb.get_process_detail(f"1{fake_adb.payload_semi}")
    Adb._is_package_installed(f"a.b{fake_adb.payload_semi}")
    Adb.get_pid_for_package_name(
        f"a.b{fake_adb.payload_sub}", use_frida_fallback=False, quiet=True
    )
    Adb.force_stop(f"a.b{fake_adb.payload_semi}")
    Adb.launch_app(f"a.b{fake_adb.payload_semi}", ".Main$(id)")
    assert not fake_adb.marker.exists()
    calls = fake_adb.calls()
    # get_process_detail refused the non-integer pid without any adb call.
    assert calls[0][:3] == ["shell", "pm", "path"]
    assert shlex.split(calls[0][3]) == [f"a.b{fake_adb.payload_semi}"]


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("get_process_detail", {"pid": "1;touch MARK;#"}),
        ("is_package_installed", {"package_name": "a.b;touch MARK;#"}),
        ("get_package_pid", {"package_name": "a.b;touch MARK;#"}),
        ("get_file_diff", {"path": "/data/local/tmp/x*;touch MARK;#"}),
    ],
)
def test_read_only_ai_tools_reject_injection(fake_adb, tool, args):
    import sandroid.ai.tools.app_query
    import sandroid.ai.tools.monitor_control
    import sandroid.ai.tools.process_control
    from sandroid.ai.tools.registry import get_tool_registry

    with pytest.raises(ToolExecutionError):
        get_tool_registry().dispatch(tool, args)
    assert not (fake_adb.marker.parent / "MARK").exists()
    assert fake_adb.calls() == []


def test_registry_rejects_wrong_argument_types():
    from sandroid.ai.tools.registry import ToolRegistry, ToolSpec

    seen = []
    reg = ToolRegistry()
    reg.register(
        ToolSpec(
            name="t",
            description="d",
            parameters={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer"},
                    "flag": {"type": "boolean"},
                    "hooks": {"type": "array", "items": {"type": "string"}},
                    "anything": {},
                },
            },
            func=lambda **kw: seen.append(kw) or "ok",
        )
    )
    assert reg.dispatch("t", {"pid": 3, "flag": False, "anything": [1]}) == "ok"
    assert reg.dispatch("t", {"pid": 3.0, "hooks": ["a"]}) == "ok"
    for bad in (
        {"pid": "3"},
        {"pid": True},
        {"flag": "yes"},
        {"hooks": "a"},
        {"hooks": ["a", 1]},
    ):
        with pytest.raises(ToolExecutionError, match="must be of type"):
            reg.dispatch("t", bad)
    assert len(seen) == 2


# ---------------------------------------------------------------------------
# C3: snapshot names, telnet console, spotlight, root/kprobe wrappers
# ---------------------------------------------------------------------------


def test_telnet_command_words_are_host_quoted(fake_adb):
    Adb.send_telnet_command(f"avd snapshot save x{fake_adb.payload_semi}")
    Adb.send_telnet_command(f"network capture start /tmp/{fake_adb.payload_sub}")
    assert not fake_adb.marker.exists()
    save, capture = fake_adb.calls()
    assert save[:4] == ["emu", "avd", "snapshot", "save"]
    # adb joins the words with spaces again: the console sees the literal text.
    assert " ".join(capture[4:]) == f"/tmp/{fake_adb.payload_sub}"


def test_snapshot_service_rejects_unsafe_names_before_adb(fake_adb):
    from sandroid.services.emulator_service import EmulatorService

    svc = EmulatorService()
    evil = f"x{fake_adb.payload_semi}"
    assert svc.create_snapshot(evil) is False
    assert svc.load_snapshot(evil) is False
    assert svc.delete_snapshot(evil) is False
    assert svc.delete_snapshot(b"..") is False
    assert fake_adb.calls() == []
    assert not fake_adb.marker.exists()


def test_snapshot_ai_tool_rejects_unsafe_name():
    from sandroid.ai.tools import environment_control

    with pytest.raises(ToolExecutionError, match="invalid snapshot name"):
        environment_control.create_snapshot("x; touch /tmp/PWNED #")


def test_spotlight_service_rejects_invalid_package():
    from sandroid.services.spotlight_service import SpotlightService

    svc = SpotlightService()
    with pytest.raises(ValueError):
        svc.set_app("com.x;touch${IFS}/tmp/PWNED;#")
    with pytest.raises(ValueError):
        svc.set_spawn_app("com.x;id")
    assert svc.get_app() is None
    svc.set_app("com.example.app")
    assert svc.get_effective_package() == "com.example.app"


def test_set_spotlight_app_tool_rejects_invalid_package():
    from sandroid.ai.tools import session_control

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        session_control.set_spotlight_app("com.x;touch${IFS}/tmp/PWNED;#")


@pytest.mark.parametrize("use_su", [True, False])
def test_root_cmd_is_one_host_word(use_su):
    from sandroid.core.proxy_manager import CAManager

    ca = CAManager()
    ca._use_su = use_su
    inner = "pkill -f \"a b\" && echo '$(id)'"
    words = shlex.split("shell " + ca._root_cmd(inner))
    assert len(words) == 2
    if use_su:
        assert shlex.split(words[1]) == ["su", "-c", inner]
    else:
        assert words[1] == inner


def test_focus_resolve_uid_rejects_invalid_package(fake_adb):
    from sandroid.core.proxy_manager import FocusManager

    assert FocusManager()._resolve_uid(f"com.a';{fake_adb.payload_semi}'") is None
    assert fake_adb.calls() == []


def test_kprobe_path_filter_is_host_safe(fake_adb):
    from sandroid.core.kprobe_tracer import KprobeTracer

    KprobeTracer._apply_path_filter(
        "/sys/kernel/tracing", [f"/data/x'{fake_adb.payload_semi}'"]
    )
    assert not fake_adb.marker.exists()
    calls = fake_adb.calls()
    assert calls
    assert all(c[0] == "shell" and len(c) == 2 for c in calls)


_SNAPSHOT_VERBS = {"create": "save", "load": "load", "delete": "del"}


@pytest.mark.parametrize("verb", sorted(_SNAPSHOT_VERBS))
def test_snapshot_console_ko_reply_is_a_failure(verb):
    """The console answers errors with "KO: ..." on stdout (adb exits 0)."""
    from sandroid.services.emulator_service import EmulatorService

    sent = []

    class _Adb:
        @staticmethod
        def send_telnet_command(command, serial=None):
            sent.append(command)
            return "KO: bad sub-command\r\n", ""

        @staticmethod
        def send_adb_command(command, serial=None):
            return "device", ""

    svc = EmulatorService(adb=_Adb())
    assert getattr(svc, f"{verb}_snapshot")("sandroid_x") is False
    assert sent == [f"avd snapshot {_SNAPSHOT_VERBS[verb]} sandroid_x"]
