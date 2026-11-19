"""Tests for the emulator launch flags and the host-memory guard."""

from __future__ import annotations

import logging
import types

import pytest

from sandroid.core import emulator_guard as eg

GB = 1024**3
_REAL_FOOTPRINT_BYTES = eg.footprint_bytes


class FakeProc:
    def __init__(self, cmdline, rss, pid=4242):
        self._cmdline = cmdline
        self._rss = rss
        self.pid = pid
        self.killed = False
        self.running = True

    def cmdline(self):
        return self._cmdline

    def memory_info(self):
        return type("M", (), {"rss": self._rss})()

    def is_running(self):
        return self.running

    def kill(self):
        self.killed = True
        self.running = False


SAFE = [
    "qemu-system-aarch64",
    "-avd",
    "X",
    "-port",
    "5556",
    "-feature",
    "-Vulkan",
    "-gpu",
    "host",
]
UNSAFE = ["qemu-system-aarch64", "-avd", "X", "-port", "5556", "-no-boot-anim"]


@pytest.fixture(autouse=True)
def _hermetic_measurements(monkeypatch, tmp_path):
    """No real ``footprint`` runs and no real AVD configs are read."""
    monkeypatch.setattr(eg, "footprint_bytes", lambda pid: None)
    avd_home = tmp_path / "avd"
    avd_home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(avd_home))
    return avd_home


def _guard(proc, monkeypatch, *, limit_gb=8, action="kill"):
    msgs: list[tuple[str, int]] = []
    adb_calls: list[list[str]] = []
    monkeypatch.setattr(eg, "find_emulator_process", lambda serial: proc)
    monkeypatch.setattr(eg.subprocess, "run", lambda argv, **kw: adb_calls.append(argv))
    # A fake clock local to the module: sleeping advances it, so the 15 s
    # "wait for emu kill" loop in _shutdown ends at once without busy-spinning
    # and without patching time.sleep for every other thread of the process.
    clock = [1000.0]
    monkeypatch.setattr(
        eg,
        "time",
        types.SimpleNamespace(
            monotonic=lambda: clock[0],
            sleep=lambda s: clock.__setitem__(0, clock[0] + s),
        ),
    )
    g = eg.EmulatorMemoryGuard(
        lambda: "emulator-5556",
        limit_gb=limit_gb,
        action=action,
        confirm_delay=0,
        adb_path_getter=lambda: "/x/adb",
        notify=lambda m, lvl: msgs.append((m, lvl)),
    )
    return g, msgs, adb_calls


def test_launch_args_disable_vulkan():
    assert eg.emulator_launch_args() == ["-feature", "-Vulkan", "-gpu", "host"]
    assert eg.emulator_launch_args(headless=True)[-1] == "swiftshader_indirect"
    assert eg.vulkan_disabled(eg.emulator_launch_args(headless=True))


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        (["-feature", "-Vulkan"], True),
        (["-feature", "GLDirectMem,-Vulkan"], True),
        (["-feature", "Vulkan"], False),
        (["-no-boot-anim"], False),
    ],
)
def test_vulkan_disabled(cmdline, expected):
    assert eg.vulkan_disabled(cmdline) is expected


def test_console_port():
    assert eg.console_port(["-avd", "A", "-port", "5558"]) == 5558
    # No -port: the emulator auto-assigns the port, it is NOT always 5554.
    assert eg.console_port(["-avd", "A"]) is None


def test_under_limit_safe_flags_is_silent(monkeypatch):
    g, msgs, adb = _guard(FakeProc(SAFE, 2 * GB), monkeypatch)
    assert g.check_once() is None
    assert msgs == []
    assert adb == []


def test_missing_vulkan_flag_warns_once(monkeypatch):
    g, msgs, _ = _guard(FakeProc(UNSAFE, 2 * GB), monkeypatch)
    g.check_once()
    g.check_once()
    warnings = [m for m, lvl in msgs if "-feature -Vulkan" in m]
    assert len(warnings) == 1


def test_near_limit_warns_once(monkeypatch):
    g, msgs, adb = _guard(FakeProc(SAFE, int(6.5 * GB)), monkeypatch)
    g.check_once()
    g.check_once()
    assert len([m for m, lvl in msgs if lvl == logging.WARNING]) == 1
    assert adb == []


def test_over_limit_kills_emulator(monkeypatch):
    proc = FakeProc(SAFE, 9 * GB)
    g, msgs, adb = _guard(proc, monkeypatch)
    assert g.check_once() == "killed"
    assert adb == [["/x/adb", "-s", "emulator-5556", "emu", "kill"]]
    assert proc.killed  # still running after emu kill -> hard kill
    assert any(lvl == logging.ERROR for _, lvl in msgs)


def test_over_limit_warn_action_does_not_kill(monkeypatch):
    proc = FakeProc(SAFE, 9 * GB)
    g, msgs, adb = _guard(proc, monkeypatch, action="warn")
    assert g.check_once() == "over-limit"
    assert adb == []
    assert not proc.killed


def test_limit_zero_disables(monkeypatch):
    proc = FakeProc(SAFE, 50 * GB)
    g, _, adb = _guard(proc, monkeypatch, limit_gb=0)
    assert g.check_once() is None
    assert adb == []


def test_non_emulator_serial_has_no_process():
    assert eg.find_emulator_process("R58M123ABC") is None
    assert eg.find_emulator_process(None) is None


def test_config_defaults():
    from sandroid.config.schema import EmulatorConfig

    cfg = EmulatorConfig()
    assert cfg.max_host_memory_gb == 10.0
    assert cfg.memory_guard_action == "kill"


# -- matching the qemu behind a serial (C4) ---------------------------------


class _Conn:
    def __init__(self, port, status="LISTEN"):
        self.laddr = type("A", (), {"port": port})()
        self.status = status


class _Qemu:
    def __init__(self, pid, cmdline, listen=(), denied=False):
        self.pid = pid
        self.info = {"name": "qemu-system-aarch64", "cmdline": cmdline}
        self._listen = listen
        self._denied = denied

    def net_connections(self, kind="tcp"):
        if self._denied:
            raise PermissionError("denied")
        return [_Conn(p) for p in self._listen] + [_Conn(1, "ESTABLISHED")]


@pytest.fixture
def procs(monkeypatch):
    import psutil

    class _Running(list):
        lsof_calls: list[int]

    running = _Running()
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: list(running))
    monkeypatch.setattr(eg, "_unidentified_serials", set())
    lsof_calls = []

    def _no_lsof(port):
        lsof_calls.append(port)

    monkeypatch.setattr(eg, "_lsof_listener_pids", _no_lsof)
    running.lsof_calls = lsof_calls
    return running


def test_explicit_port_still_matches(procs):
    procs += [
        _Qemu(1, ["qemu", "-avd", "A", "-port", "5556"]),
        _Qemu(2, ["qemu", "-avd", "B", "-port", "5554"]),
    ]
    assert eg.find_emulator_process("emulator-5554").pid == 2


def test_two_auto_port_emulators_match_by_listen_socket(procs):
    """The analyst's AVD listed first must not be taken for emulator-5554."""
    user = _Qemu(111, ["qemu", "-avd", "UserAVD"], listen=(5556, 5557))
    sandbox = _Qemu(222, ["qemu", "-avd", "Sandbox"], listen=(5554, 5555))
    procs += [user, sandbox]
    assert eg.find_emulator_process("emulator-5554") is sandbox
    assert eg.find_emulator_process("emulator-5556") is user
    assert eg.find_emulator_process("emulator-5558") is None


def test_unknown_owner_with_two_emulators_is_not_guessed(procs, caplog):
    procs += [
        _Qemu(111, ["qemu", "-avd", "UserAVD"], denied=True),
        _Qemu(222, ["qemu", "-avd", "Sandbox"], denied=True),
    ]
    with caplog.at_level(logging.WARNING):
        assert eg.find_emulator_process("emulator-5554") is None
        assert eg.find_emulator_process("emulator-5554") is None
    assert len([r for r in caplog.records if "cannot identify" in r.message]) == 1
    assert procs.lsof_calls == [5554, 5554]


def test_lsof_fallback_identifies_owner(procs, monkeypatch):
    procs += [
        _Qemu(111, ["qemu", "-avd", "UserAVD"], denied=True),
        _Qemu(222, ["qemu", "-avd", "Sandbox"], denied=True),
    ]
    monkeypatch.setattr(eg, "_lsof_listener_pids", lambda port: {222})
    assert eg.find_emulator_process("emulator-5554").pid == 222


def test_single_emulator_without_socket_info_is_matched(procs):
    procs.append(_Qemu(7, ["qemu", "-avd", "Only"], denied=True))
    assert eg.find_emulator_process("emulator-5556").pid == 7


def test_single_emulator_on_another_port_is_not_matched(procs):
    procs.append(_Qemu(7, ["qemu", "-avd", "Only"], listen=(5556,)))
    assert eg.find_emulator_process("emulator-5554") is None


def test_guard_never_kills_the_wrong_emulator(procs, monkeypatch):
    """c4 repro: user AVD (14 GB, port 5556) + sandbox (2 GB, port 5554)."""
    user = _Qemu(111, ["qemu", "-avd", "UserAVD"], listen=(5556,))
    sandbox = _Qemu(222, ["qemu", "-avd", "Sandbox", "-feature", "-Vulkan"])
    sandbox._listen = (5554,)
    for proc, rss in ((user, 14 * GB), (sandbox, 2 * GB)):
        proc.cmdline = lambda p=proc: p.info["cmdline"]
        proc.memory_info = lambda r=rss: type("M", (), {"rss": r})()
    procs += [user, sandbox]
    killed = []
    monkeypatch.setattr(eg.subprocess, "run", lambda argv, **kw: killed.append(argv))
    g = eg.EmulatorMemoryGuard(
        lambda: "emulator-5554", limit_gb=10, notify=lambda m, lvl: None
    )
    assert g.check_once() is None
    assert killed == []


# -- H1: physical footprint, RAM-scaled limit, confirm before kill -----------

FOOTPRINT_OUT = (
    "======================================================================\n"
    "qemu-system-aarch64 [39418]: 64-bit    Footprint: 9059 MB "
    "(16384 bytes per page)\n"
    "======================================================================\n"
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (FOOTPRINT_OUT, 9059 * 1024**2),
        ("Footprint: 6434 MB (16384 bytes per page)", 6434 * 1024**2),
        ("proc [1]: 64-bit    Footprint: 12 GB (16384 bytes per page)", 12 * GB),
        ("Footprint: 512 KB (16384 bytes per page)", 512 * 1024),
        ("footprint: cannot examine process 1: (os/kern) failure", None),
        ("", None),
    ],
)
def test_parse_footprint_output(text, expected):
    assert eg.parse_footprint_output(text) == expected


def test_footprint_bytes_runs_footprint_on_macos(monkeypatch):
    monkeypatch.setattr(eg, "footprint_bytes", _REAL_FOOTPRINT_BYTES)
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw.get("stdin")))
        return type("R", (), {"stdout": FOOTPRINT_OUT})()

    monkeypatch.setattr(eg.sys, "platform", "darwin")
    monkeypatch.setattr(eg.shutil, "which", lambda name: "/usr/bin/footprint")
    monkeypatch.setattr(eg.subprocess, "run", run)
    assert eg.footprint_bytes(39418) == 9059 * 1024**2
    assert calls == [(["/usr/bin/footprint", "-p", "39418"], eg.subprocess.DEVNULL)]
    monkeypatch.setattr(eg.sys, "platform", "linux")
    assert eg.footprint_bytes(39418) is None


def test_measure_prefers_footprint_and_falls_back_to_rss(monkeypatch):
    proc = FakeProc(SAFE, 15 * GB)
    assert eg.measure_host_memory(proc) == (15 * GB, "rss")
    monkeypatch.setattr(eg, "footprint_bytes", lambda pid: int(9.3 * GB))
    assert eg.measure_host_memory(proc) == (int(9.3 * GB), "footprint")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8192", 8 * GB),
        (" 8192 ", 8 * GB),
        ("2048M", 2 * GB),
        ("8G", 8 * GB),
        ("4GB", 4 * GB),
        ("junk", None),
        ("", None),
    ],
)
def test_parse_ram_size(value, expected):
    assert eg.parse_ram_size(value) == expected


def test_guest_ram_from_avd_config(_hermetic_measurements):
    avd = _hermetic_measurements / "Demo8G.avd"
    avd.mkdir()
    (avd / "config.ini").write_text("hw.ramSize=4096\nvm.heapSize=512\n")
    cmd = ["qemu-system-aarch64", "-avd", "Demo8G", "-port", "5554"]
    assert eg.guest_ram_bytes(cmd) == 4 * GB  # config.ini only
    # hardware-qemu.ini is what the running emulator resolved: it wins.
    (avd / "hardware-qemu.ini").write_text("hw.ramSize = 8192\n")
    assert eg.guest_ram_bytes(cmd) == 8 * GB
    # An explicit -memory beats both.
    assert eg.guest_ram_bytes([*cmd, "-memory", "6144"]) == 6 * GB
    assert eg.guest_ram_bytes(["qemu", "-avd", "Missing"]) is None


def test_guest_ram_follows_avd_ini_path_redirect(_hermetic_measurements, tmp_path):
    elsewhere = tmp_path / "disk" / "Big.avd"
    elsewhere.mkdir(parents=True)
    (elsewhere / "config.ini").write_text("hw.ramSize=2048\n")
    (_hermetic_measurements / "Big.ini").write_text(f"path={elsewhere}\n")
    assert eg.guest_ram_bytes(["qemu", "-avd", "Big"]) == 2 * GB


def test_effective_limit_scales_with_guest_ram():
    ten = 10 * GB
    # Measured on this host: 8 GB AVD footprint 6.5-9.3 GB, RSS up to 15.0 GB.
    assert eg.effective_limit_bytes(ten, 8 * GB, "footprint") == 12 * GB
    assert eg.effective_limit_bytes(ten, 8 * GB, "rss") == 20 * GB
    # Small AVDs keep the configured limit; a larger configured one wins.
    assert eg.effective_limit_bytes(ten, 2 * GB, "footprint") == ten
    assert eg.effective_limit_bytes(32 * GB, 8 * GB, "rss") == 32 * GB
    assert eg.effective_limit_bytes(ten, None, "rss") == ten  # RAM unknown
    assert eg.effective_limit_bytes(0, 8 * GB, "footprint") == 0  # disabled


def _avd8g(home):
    avd = home / "Demo8G.avd"
    avd.mkdir()
    (avd / "hardware-qemu.ini").write_text("hw.ramSize = 8192\n")
    return [*SAFE[:2], "Demo8G", *SAFE[3:]]


def test_h1_healthy_8g_avd_is_not_killed(monkeypatch, _hermetic_measurements):
    """H1 repro: 15.0 GB RSS / 9.3 GB footprint on an 8 GB AVD, 10 GB config."""
    proc = FakeProc(_avd8g(_hermetic_measurements), 15 * GB)
    monkeypatch.setattr(eg, "footprint_bytes", lambda pid: int(9.3 * GB))
    g, msgs, adb = _guard(proc, monkeypatch, limit_gb=10)
    assert g.check_once() is None
    assert adb == []
    assert not proc.killed
    # 9.3 GB is above 75 % of the 12 GB limit: one warning naming the rule.
    assert [lvl for _, lvl in msgs] == [logging.WARNING]
    assert "8 GB guest RAM + 4 GB" in msgs[0][0]


def test_h1_rss_fallback_does_not_kill_healthy_8g_avd(
    monkeypatch, _hermetic_measurements
):
    proc = FakeProc(_avd8g(_hermetic_measurements), 15 * GB)
    g, _, adb = _guard(proc, monkeypatch, limit_gb=10)
    assert g.check_once() is None  # RSS limit 2 x 8 + 4 = 20 GB
    assert adb == []


def test_real_leak_on_8g_avd_is_still_killed(monkeypatch, _hermetic_measurements):
    proc = FakeProc(_avd8g(_hermetic_measurements), 40 * GB)
    monkeypatch.setattr(eg, "footprint_bytes", lambda pid: 25 * GB)
    g, msgs, adb = _guard(proc, monkeypatch, limit_gb=10)
    assert g.check_once() == "killed"
    assert adb == [["/x/adb", "-s", "emulator-5556", "emu", "kill"]]
    assert any("two readings" in m for m, lvl in msgs if lvl == logging.ERROR)


def test_transient_spike_is_not_killed(monkeypatch):
    """Only a reading confirmed by a second one stops the emulator."""
    readings = iter([9 * GB, 3 * GB])
    monkeypatch.setattr(eg, "footprint_bytes", lambda pid: next(readings))
    proc = FakeProc(SAFE, 0)
    g, msgs, adb = _guard(proc, monkeypatch)
    assert g.check_once() is None
    assert adb == []
    assert not proc.killed
    assert not any(lvl == logging.ERROR for _, lvl in msgs)


def test_confirm_waits_the_confirm_delay_and_stops_cleanly(monkeypatch):
    proc = FakeProc(SAFE, 9 * GB)
    g, _, adb = _guard(proc, monkeypatch)
    waits = []
    g._stop = type("E", (), {"wait": lambda self, t: waits.append(t) or True})()
    g.confirm_delay = 7.5
    assert g.check_once() is None  # guard stopped while confirming: no kill
    assert waits == [7.5]
    assert adb == []
