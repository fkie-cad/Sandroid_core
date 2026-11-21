"""Unit tests for ``Adb``'s per-call device-serial targeting.

Covers the shared-global-race fix: passing ``serial=`` to
``Adb.send_adb_command`` / ``_build_command`` / ``send_adb_command_popen`` /
``get_android_version_and_api_level`` / ``send_telnet_command`` /
``get_current_avd_name`` must target that device WITHOUT mutating the shared
``Adb._target_device`` class attribute, while omitting ``serial`` (the
default) must behave exactly as before -- ~150 existing call sites rely on
that default being a no-op.
"""

from __future__ import annotations

import subprocess
import time

import pytest

from sandroid.core.adb import Adb
from sandroid.core.adb_utils import quote_host_arg


@pytest.fixture(autouse=True)
def _clean_target(monkeypatch):
    """Isolate the shared ADB target global across tests."""
    Adb.set_target_device(None)
    monkeypatch.setattr(Adb, "ADB_PATH", "adb")
    yield
    Adb.set_target_device(None)


class _FakeCompletedProcess:
    """Stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# _build_command
# ---------------------------------------------------------------------------


def test_build_command_serial_overrides_without_mutating_global():
    Adb.set_target_device("emulator-5554")

    result = Adb._build_command("shell getprop", serial="emulator-5556")

    assert result == "-s emulator-5556 shell getprop"
    assert Adb.get_target_device() == "emulator-5554"


def test_build_command_falls_back_to_global_when_serial_omitted():
    Adb.set_target_device("emulator-5554")

    assert Adb._build_command("shell getprop") == "-s emulator-5554 shell getprop"


def test_build_command_no_target_no_serial():
    assert Adb._build_command("devices -l") == "devices -l"


# ---------------------------------------------------------------------------
# send_adb_command / send_adb_command_popen
# ---------------------------------------------------------------------------


def test_send_adb_command_serial_targets_without_mutating_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    captured = {}

    def fake_run(cmd, **_kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess("out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    stdout, _stderr = Adb.send_adb_command("shell getprop foo", serial="emulator-5556")

    assert "-s emulator-5556" in captured["cmd"]
    assert "-s emulator-5554" not in captured["cmd"]
    assert stdout == "out"
    assert Adb.get_target_device() == "emulator-5554"  # global unaffected


def test_send_adb_command_default_uses_global_target(monkeypatch):
    """Omitting ``serial`` must preserve the pre-existing global-target behavior."""
    Adb.set_target_device("emulator-5554")
    captured = {}

    def fake_run(cmd, **_kwargs):
        captured["cmd"] = cmd
        return _FakeCompletedProcess("out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    Adb.send_adb_command("shell getprop foo")

    assert "-s emulator-5554" in captured["cmd"]


def test_send_adb_command_popen_serial_overrides_without_mutating_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    captured = {}

    class _FakePopen:
        def __init__(self, cmd, **_kwargs):
            captured["cmd"] = cmd

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)

    Adb.send_adb_command_popen("shell logcat", serial="emulator-5556")

    assert "-s emulator-5556" in captured["cmd"]
    assert Adb.get_target_device() == "emulator-5554"


# ---------------------------------------------------------------------------
# get_android_version_and_api_level
# ---------------------------------------------------------------------------


def test_get_android_version_and_api_level_serial_does_not_mutate_global(
    monkeypatch,
):
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        if "release" in command:
            return "14\n", ""
        return "34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    info = Adb.get_android_version_and_api_level(serial="emulator-5556")

    assert info == {"android_version": "14", "api_level": "34"}
    assert calls
    assert all(serial == "emulator-5556" for _cmd, serial in calls)
    assert Adb.get_target_device() == "emulator-5554"


def test_get_android_version_and_api_level_default_forwards_no_serial(monkeypatch):
    """Omitting ``serial`` must call send_adb_command exactly as before."""
    calls = []

    def fake_send(command, serial=None):
        calls.append(serial)
        return "14\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.get_android_version_and_api_level()

    assert calls

    assert all(serial is None for serial in calls)


# ---------------------------------------------------------------------------
# send_telnet_command / get_current_avd_name (the extra telnet layer)
# ---------------------------------------------------------------------------


def test_send_telnet_command_serial_does_not_mutate_global(monkeypatch):
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        return "OK\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.send_telnet_command("avd name", serial="emulator-5556")

    assert calls == [("emu avd name", "emulator-5556")]
    assert Adb.get_target_device() == "emulator-5554"


def test_get_current_avd_name_serial_forwards_through_telnet_layer(monkeypatch):
    """serial= must thread through get_current_avd_name -> _get_avd_property ->
    send_telnet_command -> send_adb_command, without touching the global.
    """
    Adb.set_target_device("emulator-5554")
    calls = []

    def fake_send(command, serial=None):
        calls.append((command, serial))
        return "Pixel_6_API_34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    name = Adb.get_current_avd_name(serial="emulator-5556")

    assert name == "Pixel_6_API_34"
    assert calls == [("emu avd name", "emulator-5556")]
    assert Adb.get_target_device() == "emulator-5554"


def test_get_current_avd_name_default_forwards_no_serial(monkeypatch):
    calls = []

    def fake_send(command, serial=None):
        calls.append(serial)
        return "Pixel_6_API_34\n", ""

    monkeypatch.setattr(Adb, "send_adb_command", fake_send)

    Adb.get_current_avd_name()

    assert calls == [None]


# ---------------------------------------------------------------------------
# _build_shell_command
# ---------------------------------------------------------------------------


def test_build_shell_command_quotes_adb_path_only_when_needed(monkeypatch):
    monkeypatch.setattr(Adb, "ADB_PATH", "adb")
    assert Adb._build_shell_command("shell getprop foo") == "adb shell getprop foo"

    monkeypatch.setattr(Adb, "ADB_PATH", "/opt/android sdk/platform-tools/adb")
    assert Adb._build_shell_command("shell getprop foo") == (
        f"{quote_host_arg('/opt/android sdk/platform-tools/adb')} shell getprop foo"
    )


def test_quote_host_arg_platform_rules():
    win_path = r"C:\Program Files\platform-tools\adb.exe"
    # cmd.exe: double quotes, backslashes preserved
    assert quote_host_arg(win_path, windows=True) == f'"{win_path}"'
    assert quote_host_arg("adb", windows=True) == "adb"
    # POSIX sh: shlex rules, plain paths untouched
    assert quote_host_arg("/usr/bin/adb", windows=False) == "/usr/bin/adb"
    assert quote_host_arg("/a b/adb", windows=False) == "'/a b/adb'"


def test_send_adb_command_passes_a_string_not_a_one_element_list(monkeypatch):
    """A one-element list + shell=True breaks on Windows.

    ``list2cmdline`` re-quotes the whole line, so it must be a plain string.
    """
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["shell"] = kwargs.get("shell")
        return _FakeCompletedProcess("", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    Adb.send_adb_command("devices -l")
    assert captured["cmd"] == "adb devices -l"
    assert captured["shell"] is True


def test_base_argv_honors_adb_path_and_target(monkeypatch):
    monkeypatch.setattr(Adb, "ADB_PATH", "/sdk/platform-tools/adb")
    assert Adb.base_argv() == ["/sdk/platform-tools/adb"]
    Adb.set_target_device("emulator-5554")
    assert Adb.base_argv() == ["/sdk/platform-tools/adb", "-s", "emulator-5554"]
    assert Adb.base_argv(serial="emulator-5556")[-1] == "emulator-5556"


# ---------------------------------------------------------------------------
# typed text never reaches the log
# ---------------------------------------------------------------------------

#: Letters none of the adb log lines contain on their own.
TYPED = "ZQXJ#WV"


def _typed_commands() -> list[str]:
    """``input text`` lines as Rewind's replay sends them (one character per
    call, quoted for the device and the host) plus a whole-word form.
    """
    from sandroid.core.adb_utils import device_shell_command
    from sandroid.features.player import input_text_arg

    one_by_one = [
        device_shell_command(f"input text {input_text_arg(c)}") for c in TYPED
    ]
    return [*one_by_one, device_shell_command(f"input text {input_text_arg(TYPED)}")]


def test_redact_typed_text_hides_every_typed_character():
    import string

    from sandroid.core.adb_utils import device_shell_command, redact_typed_text
    from sandroid.features.player import input_text_arg

    for c in string.ascii_letters + string.digits + string.punctuation:
        cmd = "-s emulator-5554 " + device_shell_command(
            f"input text {input_text_arg(c)}"
        )
        out = redact_typed_text(cmd)
        assert out == "-s emulator-5554 shell 'input text <1 char redacted>"
    assert redact_typed_text("shell input -d 0 text pw") == (
        "shell input -d 0 text <2 chars redacted>"
    )
    assert redact_typed_text("emu 'event' 'text' 'pw'") == (
        "emu 'event' 'text' <2 chars redacted>"
    )
    # character keys are typing too; named keys are not
    assert redact_typed_text("shell input keyevent KEYCODE_P 29") == (
        "shell input keyevent <2 keys redacted>"
    )
    for cmd in (
        "shell input keyevent KEYCODE_ENTER",
        "shell input keyevent 66",
        "shell input tap 10 20",
        "shell pm list packages -3",
        "shell cat /sdcard/text.txt",
        "-s emulator-5554 shell 'getprop ro.build.version.sdk'",
    ):
        assert redact_typed_text(cmd) == cmd


@pytest.mark.parametrize("path", ["run", "timeout", "popen", "root", "telnet"])
def test_typed_text_is_never_logged_but_still_executed(monkeypatch, caplog, path):
    import logging

    executed: list[str] = []

    def fake_run(cmd, *args, **kwargs):
        executed.append(cmd)
        if path == "timeout":
            raise subprocess.TimeoutExpired(cmd, 1)
        # stderr: a warning line naming the command (log_adb_result)
        return _FakeCompletedProcess(stderr="error: device offline")

    def fake_popen(cmd, *args, **kwargs):
        executed.append(cmd)
        raise OSError(f"cannot start {cmd}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    caplog.set_level(logging.DEBUG)
    commands = _typed_commands()
    for cmd in commands:
        if path in ("run", "timeout"):
            Adb.send_adb_command(cmd, serial="emulator-5554")
        elif path == "popen":
            with pytest.raises(OSError):
                Adb.send_adb_command_popen(cmd, serial="emulator-5554")
        elif path == "root":
            Adb.send_root_shell(f"input text {TYPED}")
        else:
            Adb.send_telnet_command(f"event text {TYPED}")
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "redacted" in logged
    assert not set(TYPED) & set(logged)
    # what runs is unchanged
    assert executed
    if path in ("run", "timeout", "popen"):
        assert all(cmd in run for cmd, run in zip(commands, executed, strict=True))


def test_other_commands_are_logged_unchanged(monkeypatch, caplog):
    import logging

    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _FakeCompletedProcess(stdout="ok")
    )
    caplog.set_level(logging.DEBUG)
    Adb.send_adb_command("shell pm list packages -3", serial="emulator-5554")
    logged = [r.getMessage() for r in caplog.records]
    assert "Running ADB command -s emulator-5554 shell pm list packages -3" in logged
    assert "ADB command success: -s emulator-5554 shell pm list packages -3" in logged


def test_returned_start_errors_carry_no_typed_text(monkeypatch):
    def fail(cmd, *args, **kwargs):
        raise OSError(f"cannot start {cmd}")

    monkeypatch.setattr(subprocess, "run", fail)
    for cmd in _typed_commands():
        _out, err = Adb.send_adb_command(cmd, serial="emulator-5554")
        assert err.startswith("OSError: ")
        assert "redacted" in err
        assert not set(TYPED) & set(err)


# ---------------------------------------------------------------------------
# console without authentication (texts measured on emulator 35.4.9)
# ---------------------------------------------------------------------------

_AVD_HELP_NO_AUTH = (
    "allows you to control (e.g. start/stop) the execution of the virtual device\n"
    "\n"
    "available sub-commands:\n"
    "    name             query virtual device name\n"
    "    grpc             query the grpc port\n"
    "\n"
    "KO:  bad sub-command\n"
)
_AVD_HELP_AUTH = (
    "allows you to control (e.g. start/stop) the execution of the virtual device\n"
    "\n"
    "available sub-commands:\n"
    "    stop             stop the virtual device\n"
    "    start            start/restart the virtual device\n"
    "    status           query virtual device status\n"
    "    name             query virtual device name\n"
    "    snapshot         state snapshot commands\n"
    "\n"
    "KO:  bad sub-command\n"
)


def test_console_refusals_are_told_apart_from_real_errors():
    from sandroid.core.adb_emulator import console_not_authenticated as refused

    assert refused("avd snapshot list", _AVD_HELP_NO_AUTH)
    assert refused("avd snapshot save x", _AVD_HELP_NO_AUTH)
    assert refused(
        "avd name",
        "KO: authentication token does not match ~/.emulator_console_auth_token\n",
    )
    assert refused("geo fix 1 1", "KO: unknown command, try 'help'\n")
    # an authenticated console with a real error is not a refusal
    assert not refused("avd bogus", _AVD_HELP_AUTH)
    assert not refused("frobnicate", "KO: unknown command, try 'help'\n")
    assert not refused("avd snapshot save x", "KO: snapshot save failed\n")
    assert not refused("avd snapshot list", "List of snapshots present:\nOK\n")


def test_a_refused_console_command_says_so_and_fails(monkeypatch, caplog):
    from sandroid.core import adb_emulator

    monkeypatch.setattr(adb_emulator, "_auth_warned_at", None)
    monkeypatch.setattr(
        Adb, "send_adb_command", lambda c, serial=None: (_AVD_HELP_NO_AUTH, "")
    )
    started = time.monotonic()
    with caplog.at_level("WARNING", logger="sandroid.core.adb_emulator"):
        out = Adb.send_telnet_command("avd snapshot list", serial="emulator-5556")
        Adb.send_telnet_command("avd snapshot list", serial="emulator-5556")
    assert out == ("", adb_emulator.CONSOLE_NOT_AUTHENTICATED)
    warnings = [r for r in caplog.records if "not authenticated" in r.getMessage()]
    assert len(warnings) == 1  # not once per poll
    assert adb_emulator.console_auth_failed_since(started)
    assert Adb.get_avd_snapshots() == []

    from sandroid.services.emulator_service import EmulatorService

    monkeypatch.setattr(EmulatorService, "snapshot_refusal", lambda self, *a, **k: None)
    assert EmulatorService().create_snapshot("fc_tmp", "emulator-5556") is False


def test_snapshots_panel_header_names_the_refused_console(monkeypatch):
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel, console_auth_fix

    panel = SnapshotsPanel()
    monkeypatch.setattr(panel, "_emulator_available", lambda: True)
    monkeypatch.setattr(panel, "_avd_name", lambda: "Dev6")
    assert "0 snapshot(s)" in panel._render_header()
    panel._console_refused = True
    header = panel._render_header()
    assert "snapshots can't be listed" in header
    assert "console not authenticated" in header
    assert "snapshot(s)" not in header
    # N6-V10: the fix is named instead of "no snapshots -- press c to create".
    fix = console_auth_fix()
    assert "copy ~/.emulator_console_auth_token" in fix


def test_snapshots_panel_header_without_emulator_reads_name_dot_state(monkeypatch):
    from rich.text import Text

    from sandroid.tui.themes import lens_palette
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

    panel = SnapshotsPanel()
    monkeypatch.setattr(panel, "_emulator_available", lambda: False)
    header = panel._render_header()
    dim = lens_palette().dim
    assert header == f"Emulator [{dim}]○ not running · snapshots need one[/]"
    assert Text.from_markup(header).plain == (
        "Emulator ○ not running · snapshots need one"
    )
    assert lens_palette().bad not in header
