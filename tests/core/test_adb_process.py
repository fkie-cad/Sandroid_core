"""Unit tests for sandroid.core.adb_process.

Every function under test accepts its ``send_command``/``send_root_shell``
dependency as a plain callable parameter (no ``Adb`` classmethod
monkeypatching needed, unlike the ``tests/ai/tools/`` convention) -- so tests
here just inject small scripted callables directly, matching the style
already used by :mod:`sandroid.core.adb_queries`-shaped functions.
"""

from __future__ import annotations

import pytest

from sandroid.core import adb_process
from sandroid.core.adb_process import get_process_detail, kill_pid, list_processes

# ---------------------------------------------------------------------------
# list_processes
# ---------------------------------------------------------------------------

PS_A_OUTPUT = """\
USER     PID   PPID  VSIZE  RSS   WCHAN  PC  NAME
root       1     0   12345  678   0      0   init
u0_a123  1234    1   98765  4321  0      0   com.example.app
u0_a456  1235    1   98765  4321  0      0   com.example.other
system   9999  100   11111  2222  0      0   system_server
"""


def test_list_processes_parses_every_row_and_skips_header():
    def fake_send(command):
        assert command == "shell ps -A"
        return PS_A_OUTPUT, ""

    result = list_processes(fake_send)

    assert result == [
        {"pid": 1, "user": "root", "name": "init"},
        {"pid": 1234, "user": "u0_a123", "name": "com.example.app"},
        {"pid": 1235, "user": "u0_a456", "name": "com.example.other"},
        {"pid": 9999, "user": "system", "name": "system_server"},
    ]


def test_list_processes_applies_package_filter():
    def fake_send(_command):
        return PS_A_OUTPUT, ""

    result = list_processes(fake_send, package_filter="com.example")

    assert [p["name"] for p in result] == [
        "com.example.app",
        "com.example.other",
    ]


def test_list_processes_filter_matches_no_process():
    def fake_send(_command):
        return PS_A_OUTPUT, ""

    assert list_processes(fake_send, package_filter="does.not.exist") == []


def test_list_processes_empty_output_returns_empty_list():
    def fake_send(_command):
        return "", ""

    assert list_processes(fake_send) == []


def test_list_processes_skips_short_and_malformed_lines():
    # Line 1 is a header (PID column isn't an int); line 2 is too short
    # (< 2 parts); only line 3 is a valid process row.
    output = "USER PID PPID VSIZE RSS WCHAN PC NAME\nonlyoneword\nroot 42 0 1 1 0 0 real_process"

    def fake_send(_command):
        return output, ""

    assert list_processes(fake_send) == [
        {"pid": 42, "user": "root", "name": "real_process"}
    ]


# ---------------------------------------------------------------------------
# get_process_detail
# ---------------------------------------------------------------------------

STATUS_OUTPUT = """\
Name:\tcom.example.app
State:\tS (sleeping)
Tgid:\t1234
Ngid:\t0
Pid:\t1234
PPid:\t500
TracerPid:\t0
Uid:\t10123\t10123\t10123\t10123
Gid:\t10123\t10123\t10123\t10123
Threads:\t7
VmRSS:\t45678 kB
VmSize:\t1234567 kB
"""


def _detail_send(
    status=STATUS_OUTPUT, status_err="", fd="12\n", maps="345 /proc/1234/maps\n"
):
    def fake_send(command):
        if command == "shell cat /proc/1234/status":
            return status, status_err
        if command == "shell ls /proc/1234/fd | wc -l":
            return fd, ""
        if command == "shell wc -l /proc/1234/maps":
            return maps, ""
        raise AssertionError(f"unexpected command: {command}")

    return fake_send


def test_get_process_detail_parses_status_fd_and_maps():
    result = get_process_detail(_detail_send(), 1234)

    assert result == {
        "pid": 1234,
        "name": "com.example.app",
        "state": "S (sleeping)",
        "ppid": 500,
        "threads": 7,
        "uid": 10123,
        "uid_map": {"real": 10123, "effective": 10123, "saved": 10123, "fs": 10123},
        "gid": 10123,
        "gid_map": {"real": 10123, "effective": 10123, "saved": 10123, "fs": 10123},
        "vm_rss_kb": 45678,
        "vm_size_kb": 1234567,
        "fd_count": 12,
        "map_region_count": 345,
    }


def test_get_process_detail_uid_gid_are_clean_ints_not_tab_joined():
    r"""Regression: /proc status prints Uid/Gid as 4 tab-separated ids.

    The raw ``Uid:`` line is ``10001\t10002\t10003\t10004`` (real,
    effective, saved-set, filesystem). ``uid``/``gid`` must expose the real
    id as a plain ``int`` -- never the ``"10001\t10002\t..."`` tab-joined
    string the field literally holds -- with the full set in the maps.
    """
    status = (
        "Name:\tzygote\n"
        "State:\tS (sleeping)\n"
        "Uid:\t10001\t10002\t10003\t10004\n"
        "Gid:\t20001\t20002\t20003\t20004\n"
        "Threads:\t3\n"
    )
    result = get_process_detail(_detail_send(status=status), 1234)

    assert result["uid"] == 10001
    assert isinstance(result["uid"], int)
    assert "\t" not in str(result["uid"])
    assert result["uid_map"] == {
        "real": 10001,
        "effective": 10002,
        "saved": 10003,
        "fs": 10004,
    }
    assert result["gid"] == 20001
    assert isinstance(result["gid"], int)
    assert result["gid_map"] == {
        "real": 20001,
        "effective": 20002,
        "saved": 20003,
        "fs": 20004,
    }


def test_get_process_detail_returns_none_when_process_gone():
    """Empty /proc/<pid>/status (process exited) -> None, no further reads."""
    calls = []

    def fake_send(command):
        calls.append(command)
        return "", "cat: /proc/99999/status: No such file or directory"

    assert get_process_detail(fake_send, 99999) is None
    # Only the status read should happen -- no fd/maps follow-up for a dead pid.
    assert calls == ["shell cat /proc/99999/status"]


def test_get_process_detail_returns_none_when_status_output_is_whitespace_only():
    def fake_send(_command):
        return "   \n", ""

    assert get_process_detail(fake_send, 1) is None


def test_get_process_detail_returns_none_when_name_field_missing():
    """Status text present but unparsable into a 'Name' field -> None."""
    send = _detail_send(status="garbage without colons\n")

    assert get_process_detail(send, 1234) is None


def test_get_process_detail_tolerates_missing_numeric_fields():
    status = "Name:\tstub\nState:\tZ (zombie)\n"
    send = _detail_send(status=status, fd="", maps="")

    result = get_process_detail(send, 1234)

    assert result["name"] == "stub"
    assert result["state"] == "Z (zombie)"
    assert result["ppid"] is None
    assert result["threads"] is None
    assert result["uid"] is None
    assert result["uid_map"] is None
    assert result["gid"] is None
    assert result["gid_map"] is None
    assert result["vm_rss_kb"] is None
    assert result["vm_size_kb"] is None
    assert result["fd_count"] is None
    assert result["map_region_count"] is None


# ---------------------------------------------------------------------------
# kill_pid
# ---------------------------------------------------------------------------


class ScriptedAdb:
    """Fake ``send_command``/``send_root_shell`` pair for ``kill_pid``.

    ``kill_pid``'s internal ``_alive()`` probe always polls via
    ``send_command`` -- never ``send_root_shell``, even after the root retry
    escalates the *signal* -- so only ``send_command`` consumes
    ``alive_script``. ``alive_script`` is a queue of ``(stdout, stderr))``
    tuples consumed one per ``kill -0`` probe; once exhausted, the last item
    repeats forever. ``send_root_shell`` just records whatever command it
    receives (in practice, only the root-retry signal send) and always
    reports success.
    """

    def __init__(self, alive_script):
        self._alive_script = list(alive_script)
        self.commands: list[str] = []
        self.root_commands: list[str] = []

    def send_command(self, command: str) -> tuple[str, str]:
        self.commands.append(command)
        if "kill -0" in command:
            if len(self._alive_script) > 1:
                return self._alive_script.pop(0)
            return self._alive_script[0]
        return "", ""

    def send_root_shell(self, command: str) -> tuple[str, str]:
        self.root_commands.append(command)
        return "", ""


@pytest.fixture
def fake_clock(monkeypatch):
    """Deterministic, instant-advancing stand-in for time.monotonic/sleep.

    time.sleep(interval) advances the fake clock by *interval* instead of
    actually blocking, so the settle-timeout poll loop's real-time logic
    (deadline math, multiple iterations) is exercised without slowing the
    test suite down by seconds per test.
    """
    state = {"now": 0.0}

    def fake_monotonic():
        return state["now"]

    def fake_sleep(interval):
        state["now"] += interval

    monkeypatch.setattr(adb_process.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(adb_process.time, "sleep", fake_sleep)
    return state


def test_kill_pid_dies_immediately_no_root_needed(fake_clock):
    """First post-signal probe already reports gone -> no polling, no root."""
    adb = ScriptedAdb(alive_script=[("", "no such process")])

    killed, used_root = kill_pid(adb.send_command, adb.send_root_shell, 1234, "TERM")

    assert (killed, used_root) == (True, False)
    assert adb.commands == ["shell kill -s TERM 1234", "shell kill -0 1234"]
    assert adb.root_commands == []


def test_kill_pid_detects_death_via_stderr_stream():
    """The 'gone' signal is honored whether it lands in stdout OR stderr."""
    adb = ScriptedAdb(alive_script=[("still running", "No Such Process")])

    killed, used_root = kill_pid(adb.send_command, adb.send_root_shell, 1)

    assert (killed, used_root) == (True, False)


def test_kill_pid_polls_multiple_times_before_settling_dead(fake_clock):
    """Alive on the first two probes, dead on the third -> loop actually polls."""
    adb = ScriptedAdb(
        alive_script=[
            ("still alive", ""),
            ("still alive", ""),
            ("", "no such process"),
        ]
    )

    killed, used_root = kill_pid(adb.send_command, adb.send_root_shell, 42)

    assert (killed, used_root) == (True, False)
    # Signal + 3 poll probes (2 alive, 1 dead) = 4 total kill commands.
    assert adb.commands.count("shell kill -0 42") == 3
    assert adb.root_commands == []


def test_kill_pid_falls_back_to_root_after_settle_timeout_expires(fake_clock):
    """Never settles dead within the non-root timeout -> retries via root.

    With timeout_s=2.0/interval_s=0.3, the first settle-timeout window polls
    8 times (7 in-loop + 1 final check) before giving up; 9 "alive" entries
    keep it alive through all 8 of those, and the 10th (dead) entry is only
    reached 2 probes into the *second* window (post-root-retry), proving the
    root path actually re-polls rather than trusting the retry blindly.
    """
    adb = ScriptedAdb(
        alive_script=[("still alive", "")] * 9 + [("", "no such process")]
    )

    killed, used_root = kill_pid(adb.send_command, adb.send_root_shell, 777, "KILL")

    assert (killed, used_root) == (True, True)
    assert adb.commands[0] == "shell kill -s KILL 777"
    # The root retry escalates only the *signal* via send_root_shell --
    # _alive()'s poll always goes through send_command, even post-retry.
    assert adb.root_commands == ["kill -s KILL 777"]
    assert adb.commands.count("shell kill -0 777") == 10


def test_kill_pid_reports_not_killed_when_root_retry_also_fails(fake_clock):
    """Stays alive through both the plain and root settle-timeout windows."""
    # A single "still alive" entry: since it's never popped down to zero, the
    # fake keeps returning it forever -- i.e. the process never dies.
    adb = ScriptedAdb(alive_script=[("still alive", "")])

    killed, used_root = kill_pid(adb.send_command, adb.send_root_shell, 5)

    assert (killed, used_root) == (False, True)
    assert adb.root_commands == ["kill -s TERM 5"]  # root retry attempted, once


def test_kill_pid_coerces_string_pid():
    adb = ScriptedAdb(alive_script=[("", "no such process")])

    killed, _used_root = kill_pid(adb.send_command, adb.send_root_shell, "123")

    assert killed is True
    assert adb.commands[0] == "shell kill -s TERM 123"


def test_kill_pid_rejects_non_integer_pid():
    adb = ScriptedAdb(alive_script=[("", "no such process")])

    with pytest.raises(ValueError):
        kill_pid(adb.send_command, adb.send_root_shell, "not-a-pid")

    # Must fail before ever touching the shell.
    assert adb.commands == []


def test_kill_pid_rejects_signal_outside_allowlist():
    adb = ScriptedAdb(alive_script=[("", "no such process")])

    with pytest.raises(ValueError, match="unsupported signal"):
        kill_pid(adb.send_command, adb.send_root_shell, 1, signal="STOP")

    assert adb.commands == []


@pytest.mark.parametrize("signal", ["TERM", "KILL", "HUP", "INT"])
def test_kill_pid_accepts_every_allowlisted_signal(signal):
    adb = ScriptedAdb(alive_script=[("", "no such process")])

    killed, _used_root = kill_pid(adb.send_command, adb.send_root_shell, 1, signal)

    assert killed is True
    assert adb.commands[0] == f"shell kill -s {signal} 1"
