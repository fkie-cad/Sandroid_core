"""EmulatorService on the session timeline: snapshot lines, the world change
of a load (before anything samples the restored clocks), the cold boot.
"""

from __future__ import annotations

import time

import pytest

from sandroid.core import device_clock, timeline
from sandroid.services.emulator_service import EmulatorService


class _Adb:
    def __init__(self, reply=("OK\n", "")) -> None:
        self.reply = reply
        self.order: list[str] = []

    def send_telnet_command(self, command, serial=None):
        self.order.append(f"telnet {command}")
        return self.reply

    def send_adb_command(self, command, serial=None):
        self.order.append(command)
        return ("device\n", "") if command == "get-state" else ("", "")

    def get_target_device(self):
        return "emu-1"


@pytest.fixture
def service(monkeypatch):
    svc = EmulatorService()
    adb = _Adb()
    svc._get_adb = lambda: adb
    monkeypatch.setattr(svc, "_restore_device_proxy", lambda serial: "skipped")
    monkeypatch.setattr(svc, "_restore_selinux_permissive", lambda adb, serial: None)
    svc.adb_fake = adb
    return svc


def test_a_load_is_a_world_change_before_the_clock_is_sampled(service, monkeypatch):
    seen = []

    def record(adb, name, serial):
        seen.append([(x["src"], x["kind"]) for x in lines])

    monkeypatch.setattr(service, "_record_device_clock", record)
    barrier = []
    monkeypatch.setattr(device_clock, "begin_epoch", barrier.append)
    with timeline.capture() as lines:
        sent = time.time()
        assert service.load_snapshot("clean", serial="emu-1") is True
    assert seen == [[("snapshot", "load")]]
    assert barrier == ["emu-1"]
    (world,) = lines
    assert world["actor"] == "sandroid"
    assert (world["world"], world["epoch"], world["dev"]) == (1, 1, "emu-1")
    assert world["data"]["name"] == "clean"
    assert world["data"]["ok"] is True
    assert world["data"]["cause"] == "snapshot-load"
    assert world["data"]["console_ms"] >= 0
    assert world["summary"] == "⟲ snapshot 'clean' loaded"
    assert "t_err_ms" in world
    assert world["t"] >= timeline._iso(sent)


def test_a_load_restores_selinux_before_the_clock_step(service, monkeypatch):
    """Ready -> SELinux Permissive -> clock record/sync -> device proxy:
    under Enforcing the clock step's root reads and ``date`` may be denied.
    """
    steps: list[str] = []
    monkeypatch.setattr(
        service, "_wait_for_device_ready", lambda adb, serial: steps.append("ready")
    )
    monkeypatch.setattr(
        service,
        "_restore_selinux_permissive",
        lambda adb, serial: steps.append("selinux"),
    )
    monkeypatch.setattr(
        service, "_record_device_clock", lambda adb, name, serial: steps.append("clock")
    )
    monkeypatch.setattr(
        service, "_restore_device_proxy", lambda serial: steps.append("proxy")
    )
    monkeypatch.setattr(device_clock, "begin_epoch", lambda serial: None)
    with timeline.capture():
        assert service.load_snapshot("clean", serial="emu-1") is True
    assert steps == ["ready", "selinux", "clock", "proxy"]


def test_a_failed_load_is_a_warning_and_no_world_change(service):
    service.adb_fake.reply = ("KO: unknown snapshot\n", "")
    with timeline.acting_as("user"), timeline.capture() as lines:
        assert service.load_snapshot(b"gone", serial="emu-1") is False
    (line,) = lines
    assert (line["src"], line["kind"], line["level"]) == ("snapshot", "load", "warn")
    assert line["world"] == 0
    assert line["data"]["ok"] is False
    assert line["data"]["name"] == "gone"
    assert "KO" in line["data"]["error"]
    assert line["actor"] == "user"


def test_save_and_delete_lines(service):
    with timeline.capture() as lines:
        assert service.create_snapshot("tmp", serial="emu-1") is True
        assert service.delete_snapshot("tmp") is True
        service.adb_fake.reply = ("", "boom")
        assert service.create_snapshot("tmp", serial="emu-1") is False
    assert [(x["kind"], x["data"]["ok"]) for x in lines] == [
        ("save", True),
        ("delete", True),
        ("save", False),
    ]
    assert lines[0]["summary"] == "snapshot 'tmp' saved"
    assert lines[2]["level"] == "warn"


def test_a_cold_boot_is_a_world_change(service, monkeypatch):
    from types import SimpleNamespace

    import sandroid.core.emulator as emulator_mod

    service.adb_fake.get_target_device = lambda: "emulator-5556"
    monkeypatch.setattr(emulator_mod, "emulator_binary", lambda: "/bin/emulator")
    monkeypatch.setattr(
        emulator_mod,
        "restart_emulator",
        lambda serial, adb=None: SimpleNamespace(avd="Pixel", log_path=None),
    )
    monkeypatch.setattr(emulator_mod, "wait_until_ready", lambda *a, **kw: True)
    monkeypatch.setattr(device_clock, "begin_epoch", lambda serial: None)
    with timeline.capture() as lines:
        assert service.restart(boot_timeout=1) is True
    (boot,) = lines
    assert (boot["src"], boot["kind"], boot["world"]) == ("device", "boot", 1)
    assert boot["data"]["cause"] == "cold-boot"
    assert boot["data"]["ok"] is True
