"""Pure parts of the emulator backend + device parsing.

Covers: the one ``adb devices`` parser; the emulator command builder per boot
mode; the console port picker; SDK/AVD discovery precedence and the ``.ini``
``path=`` / ``path.rel=`` redirect; ``avd_info`` / ``avd_snapshots``;
``list_avds``; remembered launch options; ``rename_avd``; ``Adb.init``
raising instead of exiting; DeviceManager root kinds and auto-select skipping
our booting launches.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.core import emulator as emu
from sandroid.core.device import Device, DeviceCapability, parse_adb_devices
from sandroid.core.emulator import AvdLaunchOptions
from sandroid.core.exceptions import AdbNotFoundError, EmulatorLaunchError

# -- parse_adb_devices --------------------------------------------------------


def test_parse_tab_format_skips_header_and_daemon_lines():
    text = (
        "* daemon not running; starting now at tcp:5037\n"
        "* daemon started successfully\n"
        "List of devices attached\n"
        "emulator-5554\tdevice\n"
        "emulator-5556\toffline\n"
        "R58N123ABC\tunauthorized\n"
        "\n"
    )
    entries = parse_adb_devices(text)
    assert [(e.serial, e.state, e.props) for e in entries] == [
        ("emulator-5554", "device", {}),
        ("emulator-5556", "offline", {}),
        ("R58N123ABC", "unauthorized", {}),
    ]


def test_parse_long_format_props():
    text = (
        "List of devices attached\n"
        "emulator-5554          device product:sdk_gphone64_arm64 "
        "model:sdk_gphone64_arm64 device:emu64a transport_id:1\n"
        "192.168.1.5:5555       device product:x model:Pixel_7 device:p "
        "transport_id:4\n"
    )
    first, second = parse_adb_devices(text)
    assert first.serial == "emulator-5554"
    assert first.state == "device"
    assert first.props == {
        "product": "sdk_gphone64_arm64",
        "model": "sdk_gphone64_arm64",
        "device": "emu64a",
        "transport_id": "1",
    }
    assert (second.serial, second.props["model"]) == ("192.168.1.5:5555", "Pixel_7")


@pytest.mark.parametrize(
    "line",
    [
        "0123456789ABCDEF\tno permissions (missing udev rules? user is in the "
        "plugdev group); see [http://developer.android.com/tools/device.html]",
        "0123456789ABCDEF       no permissions (missing udev rules? user is in "
        "the plugdev group); see [http://developer.android.com/tools/device.html]"
        " usb:1-1 transport_id:3",
    ],
)
def test_parse_no_permissions_is_one_state(line):
    (entry,) = parse_adb_devices("List of devices attached\n" + line + "\n")
    assert entry.serial == "0123456789ABCDEF"
    assert entry.state == "no permissions"
    if "usb:" in line:
        assert entry.props == {"usb": "1-1", "transport_id": "3"}


def test_parse_garbage_and_empty():
    assert parse_adb_devices("") == []
    assert parse_adb_devices("List of devices attached\n\n") == []
    assert parse_adb_devices("error: protocol fault\n") == []


# -- command builder / port picker ---------------------------------------------


@pytest.mark.parametrize(
    ("opts", "tail"),
    [
        (AvdLaunchOptions(), []),
        (AvdLaunchOptions(boot="cold"), ["-no-snapshot-load"]),
        (AvdLaunchOptions(boot="wipe"), ["-wipe-data"]),
        (AvdLaunchOptions(boot="snapshot", snapshot="clean"), ["-snapshot", "clean"]),
        (AvdLaunchOptions(boot="snapshot"), []),
        (AvdLaunchOptions(extra_args=("-no-audio",)), ["-no-audio"]),
    ],
)
def test_build_emulator_command_boot_modes(opts, tail):
    cmd = emu.build_emulator_command("/sdk/emulator", "Pixel", 5560, opts)
    assert cmd == [
        "/sdk/emulator",
        "-avd",
        "Pixel",
        "-port",
        "5560",
        "-feature",
        "-Vulkan",
        "-gpu",
        "host",
        *tail,
    ]


def test_build_emulator_command_headless():
    cmd = emu.build_emulator_command(
        "/sdk/emulator", "Pixel", 5554, AvdLaunchOptions(headless=True, boot="cold")
    )
    assert cmd[5:] == [
        "-feature",
        "-Vulkan",
        "-gpu",
        "swiftshader_indirect",
        "-no-window",
        "-no-boot-anim",
        "-no-snapshot-load",
    ]


def test_free_console_port_skips_taken_and_busy(monkeypatch):
    busy = {5556}
    monkeypatch.setattr(emu, "_ports_free", lambda p: p not in busy)
    assert emu.free_console_port(set()) == 5554
    assert emu.free_console_port({5554}) == 5558
    with pytest.raises(EmulatorLaunchError, match="No free emulator console port"):
        emu.free_console_port(set(range(5554, 5586)))


def test_port_bindable_ignores_time_wait_but_not_a_listener():
    """Right after ``emu kill`` the console/adb ports sit in TIME_WAIT for
    30-60 s; a restart on the same port must not wait for that.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _addr = server.accept()
    assert emu._port_bindable(port) is False  # live listener
    # The side that closes first keeps (127.0.0.1, port) in TIME_WAIT.
    accepted.close()
    client.recv(1)  # EOF: the FIN arrived
    client.close()
    server.close()
    if os.name != "nt":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as plain:
            with pytest.raises(OSError):  # really in TIME_WAIT
                plain.bind(("127.0.0.1", port))
    assert emu._port_bindable(port) is True


def test_port_bindable_detects_a_bound_port():
    # An ephemeral port, never one a real emulator could be using.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        assert emu._port_bindable(port) is False
    assert emu.serial_port("emulator-5584") == 5584
    assert emu.serial_port("R58N123ABC") is None


# -- discovery ----------------------------------------------------------------


@pytest.fixture
def no_config(monkeypatch, tmp_path):
    cfg = SimpleNamespace(
        avd_home=None,
        sdk_path=None,
        android_emulator_path=None,
        adb_path=None,
        avd_headless=False,
    )
    monkeypatch.setattr(emu, "_config_emulator", lambda: cfg)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for var in (
        "ANDROID_AVD_HOME",
        "ANDROID_EMULATOR_HOME",
        "ANDROID_USER_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_HOME",
    ):
        monkeypatch.delenv(var, raising=False)
    return cfg


def test_avd_home_precedence(no_config, tmp_path, monkeypatch):
    dirs = {name: tmp_path / name for name in ("cfg", "avdhome", "emuhome", "userhome")}
    (dirs["emuhome"] / "avd").mkdir(parents=True)
    (dirs["userhome"] / "avd").mkdir(parents=True)
    dirs["cfg"].mkdir()
    dirs["avdhome"].mkdir()
    default = tmp_path / "home" / ".android" / "avd"
    default.mkdir(parents=True)

    assert emu.avd_home() == default
    monkeypatch.setenv("ANDROID_USER_HOME", str(dirs["userhome"]))
    assert emu.avd_home() == dirs["userhome"] / "avd"
    monkeypatch.setenv("ANDROID_EMULATOR_HOME", str(dirs["emuhome"]))
    assert emu.avd_home() == dirs["emuhome"] / "avd"
    monkeypatch.setenv("ANDROID_AVD_HOME", str(dirs["avdhome"]))
    assert emu.avd_home() == dirs["avdhome"]
    no_config.avd_home = dirs["cfg"]
    assert emu.avd_home() == dirs["cfg"]
    no_config.avd_home = tmp_path / "missing"  # nonexistent: falls through
    assert emu.avd_home() == dirs["avdhome"]


def _make_avd(home: Path, name: str, directory: Path | None = None, ini=""):
    directory = directory or home / f"{name}.avd"
    directory.mkdir(parents=True, exist_ok=True)
    (home / f"{name}.ini").write_text(ini or f"path={directory}\n")
    return directory


def test_avd_dir_follows_path_then_path_rel(no_config, tmp_path, monkeypatch):
    home = tmp_path / "user" / "avd"
    home.mkdir(parents=True)
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    elsewhere = _make_avd(home, "Far", tmp_path / "disk" / "Far.avd")
    assert emu.avd_dir("Far") == elsewhere

    rel = _make_avd(
        home, "Rel", home / "Rel.avd", ini="path=/gone\npath.rel=avd/Rel.avd\n"
    )
    assert emu.avd_dir("Rel") == tmp_path / "user" / "avd" / "Rel.avd" == rel

    plain = home / "Plain.avd"
    plain.mkdir()
    assert emu.avd_dir("Plain") == plain
    assert emu.avd_dir("Missing") is None


def test_avd_info_and_snapshots_through_redirect(no_config, tmp_path, monkeypatch):
    home = tmp_path / "avd"
    home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    directory = _make_avd(home, "Pixel_API_35", tmp_path / "big" / "x.avd")
    (directory / "config.ini").write_text(
        "image.sysdir.1=system-images/android-35/google_apis_playstore/arm64-v8a/\n"
        "hw.device.name=pixel_8\n"
    )
    snaps = directory / "snapshots"
    for name, marker in (
        ("default_boot", "snapshot.pb"),
        ("clean", "hardware.ini"),
        ("junk", None),
    ):
        (snaps / name).mkdir(parents=True)
        if marker:
            (snaps / name / marker).write_text("")
    (snaps / "clean" / "ram.bin").write_bytes(b"\0" * 2048)

    info = emu.avd_info("Pixel_API_35")
    assert info.api_level == 35
    assert info.android_version == "15"
    assert info.tag == "google_apis_playstore"
    assert info.abi == "arm64-v8a"
    assert info.device_name == "pixel_8"
    assert info.path == directory
    assert info.snapshot_count == 2
    assert [s.name for s in emu.avd_snapshots("Pixel_API_35")] == [
        "default_boot",
        "clean",
    ]


def test_avd_info_falls_back_to_ini_target(no_config, tmp_path, monkeypatch):
    home = tmp_path / "avd"
    home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    d = home / "Old.avd"
    d.mkdir()
    (home / "Old.ini").write_text(f"path={d}\ntarget=android-30\n")
    (d / "config.ini").write_text("tag.id=default\nabi.type=x86_64\n")
    info = emu.avd_info("Old")
    assert (info.api_level, info.tag, info.abi) == (30, "default", "x86_64")
    assert emu.avd_info("Nope").api_level is None


def test_emulator_binary_prefers_config_then_sdk_then_path(
    no_config, tmp_path, monkeypatch
):
    sdk = tmp_path / "sdk"
    (sdk / "platform-tools").mkdir(parents=True)
    sdk_emu = sdk / "emulator" / "emulator"
    sdk_emu.parent.mkdir()
    on_path = tmp_path / "bin" / "emulator"
    on_path.parent.mkdir()
    for exe in (sdk_emu, on_path):
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(on_path.parent))
    assert emu.emulator_binary() == on_path
    monkeypatch.setenv("ANDROID_SDK_ROOT", str(sdk))
    assert emu.sdk_root() == sdk
    assert emu.emulator_binary() == sdk_emu
    configured = tmp_path / "custom" / "emulator"
    configured.parent.mkdir()
    configured.write_text("#!/bin/sh\n")
    configured.chmod(0o755)
    no_config.android_emulator_path = configured
    assert emu.emulator_binary() == configured


def test_emulator_env_points_at_resolved_dirs(no_config, tmp_path, monkeypatch):
    sdk = tmp_path / "sdk"
    (sdk / "platform-tools").mkdir(parents=True)
    home = tmp_path / "avd"
    home.mkdir()
    no_config.sdk_path = sdk
    no_config.avd_home = home
    env = emu.emulator_env()
    assert env["ANDROID_SDK_ROOT"] == env["ANDROID_HOME"] == str(sdk)
    assert env["ANDROID_AVD_HOME"] == str(home)


# -- list_avds ------------------------------------------------------------------


def test_list_avds_filters_info_lines(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs, cmd=cmd)
        return SimpleNamespace(
            returncode=0,
            stdout="INFO    | Storing crashdata in: /tmp/x\nPixel_API_35\n\nSmall\n",
        )

    monkeypatch.setattr(emu.subprocess, "run", fake_run)
    assert emu.list_avds(timeout=7, binary="/sdk/emulator") == [
        "Pixel_API_35",
        "Small",
    ]
    assert seen["cmd"] == ["/sdk/emulator", "-list-avds"]
    assert seen["timeout"] == 7


def test_list_avds_timeout_and_missing_binary(monkeypatch):
    def slow(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(emu.subprocess, "run", slow)
    assert emu.list_avds(binary="/sdk/emulator") == []
    monkeypatch.setattr(emu, "emulator_binary", lambda: None)
    assert emu.list_avds() == []


# -- remembered launch options --------------------------------------------------


def test_prefs_round_trip_never_store_wipe(no_config, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert emu.load_launch_prefs() == {
        "schema_version": 1,
        "last_avd": None,
        "avds": {},
    }
    no_config.avd_headless = True
    assert emu.remembered_options("New") == AvdLaunchOptions(headless=True)

    emu.remember_launch("A", AvdLaunchOptions(headless=True, boot="wipe"))
    emu.remember_launch("B", AvdLaunchOptions(boot="snapshot", snapshot="clean"))
    prefs = emu.load_launch_prefs()
    assert prefs["last_avd"] == "B"
    assert prefs["avds"]["A"] == {"headless": True, "boot": "normal", "snapshot": None}
    assert emu.remembered_options("A") == AvdLaunchOptions(headless=True)
    assert emu.remembered_options("B") == AvdLaunchOptions(
        boot="snapshot", snapshot="clean"
    )
    path = tmp_path / "xdg" / "sandroid" / "devices.json"
    assert path.is_file()

    path.write_text("{not json")
    assert emu.load_launch_prefs()["avds"] == {}


def test_rename_avd_moves_dir_ini_and_prefs(no_config, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    home = tmp_path / "avd"
    home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    _make_avd(
        home,
        "Old",
        ini=f"avd.ini.encoding=UTF-8\npath={home / 'Old.avd'}\n"
        "path.rel=avd/Old.avd\n",
    )
    emu.remember_launch("Old", AvdLaunchOptions(headless=True))

    ok, msg = emu.rename_avd("Old", "New_1")
    assert ok, msg
    assert not (home / "Old.ini").exists()
    assert (home / "New_1.avd").is_dir()
    ini = (home / "New_1.ini").read_text()
    assert f"path={home / 'New_1.avd'}" in ini
    assert "path.rel=avd/New_1.avd" in ini
    assert emu.avd_dir("New_1") == home / "New_1.avd"
    prefs = emu.load_launch_prefs()
    assert prefs["last_avd"] == "New_1"
    assert "Old" not in prefs["avds"]

    assert emu.rename_avd("New_1", "1bad")[0] is False
    assert emu.rename_avd("Ghost", "Other")[0] is False


def test_avd_lock_files_ignore_multiinstance_and_dead_pids(
    no_config, tmp_path, monkeypatch
):
    home = tmp_path / "avd"
    home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    _make_avd(home, "Pixel")
    directory = home / "Pixel.avd"
    # Left behind by every clean exit (the emulator only flocks it).
    (directory / "multiinstance.lock").write_text("")
    assert emu.avd_lock_files("Pixel") == []
    dead = subprocess.Popen([sys.executable, "-I", "-c", "pass"])
    dead.wait(timeout=30)
    (directory / "hardware-qemu.ini.lock").write_text(f"{dead.pid} ")
    assert emu.avd_lock_files("Pixel") == []  # a crashed emulator's lock
    (directory / "hardware-qemu.ini.lock").write_text(f"{os.getpid()} ")
    assert [p.name for p in emu.avd_lock_files("Pixel")] == [
        "hardware-qemu.ini.lock"
    ]
    (directory / "hardware-qemu.ini.lock").unlink()
    (directory / "userdata-qemu.img.lock").mkdir()  # Windows-style lock dir
    assert [p.name for p in emu.avd_lock_files("Pixel")] == [
        "userdata-qemu.img.lock"
    ]
    assert emu.avd_lock_files("Ghost") == []


def test_rename_avd_refuses_a_running_avd(no_config, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    home = tmp_path / "avd"
    home.mkdir()
    monkeypatch.setenv("ANDROID_AVD_HOME", str(home))
    _make_avd(home, "Busy")
    lock = home / "Busy.avd" / "hardware-qemu.ini.lock"
    lock.write_text(f"{os.getpid()}")
    ok, msg = emu.rename_avd("Busy", "Renamed")
    assert not ok
    assert "hardware-qemu.ini.lock" in msg
    assert (home / "Busy.ini").exists()
    assert (home / "Busy.avd").is_dir()
    lock.unlink()

    class _Alive:
        def poll(self):
            return None

    launch = emu.EmulatorLaunch(
        "Busy", "emulator-5570", 5570, AvdLaunchOptions(), _Alive(), None, 0.0
    )
    monkeypatch.setattr(emu, "_LAUNCHES", {launch.serial: launch})
    ok, msg = emu.rename_avd("Busy", "Renamed")
    assert not ok
    assert "emulator-5570" in msg
    monkeypatch.setattr(emu, "_LAUNCHES", {})
    assert emu.rename_avd("Busy", "Renamed")[0] is True


# -- Adb.init / missing adb ----------------------------------------------------


def test_adb_init_raises_instead_of_exiting(monkeypatch):
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "ADB_PATH", None)
    monkeypatch.setattr(emu, "adb_binary", lambda: None)
    with pytest.raises(AdbNotFoundError):
        Adb.init()
    assert isinstance(AdbNotFoundError("x"), OSError)
    stdout, stderr = Adb.send_adb_command("devices")
    assert stdout == ""
    assert stderr.lower().startswith("oserror:")
    assert "adb not found" in stderr


def test_adb_init_uses_adb_binary(monkeypatch):
    from sandroid.core.adb import Adb

    monkeypatch.setattr(Adb, "ADB_PATH", None)
    monkeypatch.setattr(emu, "adb_binary", lambda: Path("/opt/sdk/adb"))
    Adb.init()
    assert Adb.ADB_PATH == "/opt/sdk/adb"


# -- DeviceManager: root kinds, booting launches ------------------------------


@pytest.fixture
def dm(monkeypatch):
    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager

    DeviceManager.reset()
    Adb.set_target_device(None)
    yield DeviceManager.get()
    DeviceManager.reset()
    Adb.set_target_device(None)


@pytest.mark.parametrize(
    ("serial", "replies", "kind", "rooted"),
    [
        ("emulator-5554", {"shell id -u": "0\n"}, "adbd root", True),
        (
            "emulator-5554",
            {"shell id -u": "2000\n", "shell getprop ro.build.type": "userdebug\n"},
            "adb root",
            True,
        ),
        (
            "emulator-5554",
            {"shell id -u": "2000\n", "shell getprop ro.build.type": "user\n"},
            "none",
            False,
        ),
        (  # Magisk on a user-build emulator image
            "emulator-5554",
            {
                "shell id -u": "2000\n",
                "shell getprop ro.build.type": "user\n",
                "shell su -c id": "uid=0(root) gid=0(root)\n",
            },
            "su",
            True,
        ),
        ("R58N123ABC", {"shell su -c id": "uid=0(root) gid=0(root)"}, "su", True),
        ("R58N123ABC", {"shell su -c id": ""}, "none", False),
    ],
)
def test_root_kind_probe(dm, monkeypatch, serial, replies, kind, rooted):
    from sandroid.core.adb import Adb

    calls = []

    def fake(command, serial=None, timeout=30):
        if command == "shell su -c id":
            assert timeout <= 5  # a root prompt must not stall the probe
        calls.append(serial)
        return replies.get(command, "14\n" if "getprop" in command else ""), ""

    monkeypatch.setattr(Adb, "send_adb_command", fake)
    device = Device(serial=serial)
    assert not device.has_capability(DeviceCapability.ADB_ROOT)
    dm._populate_device_info(device)
    assert device.root_kind == kind
    assert device.has_capability(DeviceCapability.ADB_ROOT) is rooted
    assert set(calls) == {serial}


def test_auto_select_skips_our_booting_launch(dm, monkeypatch):
    monkeypatch.setattr(emu, "booting_serials", lambda: ["emulator-5556"])
    selected = []
    monkeypatch.setattr(
        type(dm), "set_active_device", lambda self, s: selected.append(s) or True
    )
    dm._devices = {
        "emulator-5556": Device(serial="emulator-5556"),
        "emulator-5558": Device(serial="emulator-5558"),
    }
    picked = dm.auto_select_device()
    assert picked is not None
    assert picked.serial == "emulator-5558"
    assert selected == ["emulator-5558"]

    dm._devices = {"emulator-5556": Device(serial="emulator-5556")}
    selected.clear()
    assert dm.auto_select_device() is None
    assert selected == []


class AdbTable:
    """adb transport double: ``devices -l`` from a table, per-serial props."""

    def __init__(self):
        self.devices: dict[str, str] = {}
        self.calls: list[tuple[str, str | None]] = []

    def send(self, command, serial=None, timeout=30):
        self.calls.append((command, serial))
        if command.startswith("devices"):
            rows = "".join(f"{s}\tdevice\n" for s in self.devices)
            return "List of devices attached\n" + rows + "\n", ""
        if serial not in self.devices:
            return "", f"error: device '{serial}' not found"
        if command == "shell getprop ro.build.version.release":
            return "15\n", ""
        if command == "shell getprop ro.build.version.sdk":
            return "35\n", ""
        if command == "shell id -u":
            return "0\n", ""
        if "avd_name" in command:
            return self.devices[serial] + "\n", ""
        return "", ""


@pytest.fixture
def adb_table(dm, monkeypatch):
    from sandroid.core import device_clock
    from sandroid.core.adb import Adb
    from sandroid.core.device_manager import DeviceManager

    table = AdbTable()
    monkeypatch.setattr(Adb, "send_adb_command", table.send)
    monkeypatch.setattr(DeviceManager, "_preferred_serial", None)
    connected: list[str] = []
    monkeypatch.setattr(
        device_clock, "after_device_connect_async", connected.append
    )
    table.connected = connected
    return table


def test_lost_device_is_reconnected_but_never_replaced(dm, adb_table):
    """After the active device is gone, the session waits for it: another
    device -- even the only ready one -- is never selected silently.
    """
    changes = []
    dm.on_device_change(changes.append)
    adb_table.devices = {"emulator-5554": "Mine"}
    dm.refresh_devices()  # first start: the only ready device is taken
    assert dm.active_device.serial == "emulator-5554"

    adb_table.devices = {"emulator-5556": "Theirs"}  # mine stopped/restarting
    dm.refresh_devices()
    assert dm.active_device is None
    assert changes[-1] is None
    dm.refresh_devices()
    assert dm.active_device is None  # still not moved to emulator-5556

    adb_table.devices = {"emulator-5554": "Mine", "emulator-5556": "Theirs"}
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5554"
    assert adb_table.connected == ["emulator-5554", "emulator-5554"]


def test_attaching_another_device_moves_the_pin(dm, adb_table, monkeypatch):
    from sandroid.core.device_manager import DeviceManager

    monkeypatch.setattr(DeviceManager, "_preferred_serial", "emulator-5554")
    adb_table.devices = {"emulator-5554": "Mine", "emulator-5556": "Other"}
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5554"
    other = dm.get_device("emulator-5556")
    assert other.android_version == ""  # the pin rule: never probed
    probed_other = [c for c in adb_table.calls if c[1] == "emulator-5556"]
    assert probed_other == []

    assert dm.set_active_device("emulator-5556") is True  # Devices screen ⏎
    assert DeviceManager.preferred_serial() == "emulator-5556"
    assert other.android_version == "15"
    assert other.api_level == 35
    assert other.root_kind == "adbd root"
    assert adb_table.connected[-1] == "emulator-5556"  # device clock hook

    adb_table.devices = {"emulator-5554": "Mine"}
    dm.refresh_devices()
    assert dm.active_device is None  # not back to the old pin
    adb_table.devices = {"emulator-5554": "Mine", "emulator-5556": "Other"}
    dm.refresh_devices()
    assert dm.active_device.serial == "emulator-5556"


def test_get_avd_name_for_device_uses_backend(dm, monkeypatch):
    from sandroid.core.adb import Adb

    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        lambda command, serial=None, timeout=30: (
            ("Pixel_API_35\n", "") if "avd_name" in command else ("", "")
        ),
    )
    device = Device(serial="emulator-5554")
    assert dm.get_avd_name_for_device(device) == "Pixel_API_35"


def test_no_real_device_env_leaks():
    # The suite runs with ANDROID_* scrubbed (tests/conftest.py).
    assert "ANDROID_SERIAL" not in os.environ
