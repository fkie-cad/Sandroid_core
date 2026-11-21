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
    assert world["summary"] == "snapshot 'clean' loaded"
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


def test_a_load_without_a_serial_changes_only_the_targets_world(service, monkeypatch):
    from sandroid.services import identity

    forgotten: list = []

    class _Ident:
        def sim_launch_changed(self, serial):
            pass

        def forget(self, serial=None, *, restored=False):
            forgotten.append((serial, restored))

    monkeypatch.setattr(identity, "get_identity_service", lambda: _Ident())
    monkeypatch.setattr(service, "_record_device_clock", lambda *a: None)
    with timeline.capture() as lines:
        assert service.load_snapshot("clean") is True
    assert forgotten == [("emu-1", True)]  # the target only, not every device
    assert [x["dev"] for x in lines] == ["emu-1"]


def test_a_load_holds_the_device_its_world_change_names(service, monkeypatch):
    from sandroid.core import device_prep

    held: list = []

    class _Hold:
        def __init__(self, serial, cause):
            held.append(serial)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(device_prep, "hold", _Hold)
    monkeypatch.setattr(service, "_record_device_clock", lambda *a: None)
    service.adb_fake.get_target_device = lambda: None  # no adb target
    monkeypatch.setattr(service, "_target_serial", lambda adb: "emu-9")
    with timeline.capture() as lines:
        assert service.load_snapshot("clean") is True
    assert held == ["emu-9"]
    assert {x["dev"] for x in lines} <= {"emu-9", None}


# ---------------------------------------------------------------------------
# N4-B2 / N4-B7: the network step of every load, and a load that completes
# after the console gave up
# ---------------------------------------------------------------------------


def _wait(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def test_every_load_resets_the_network_unless_the_caller_does(service, monkeypatch):
    from sandroid.services import emulator_service as es

    resets: list = []
    monkeypatch.setattr(
        es, "reset_network_after_load", lambda serial, **kw: resets.append(serial)
    )
    monkeypatch.setattr(service, "_record_device_clock", lambda *a: None)
    with timeline.capture():
        assert service.load_snapshot("clean", serial="emu-1") is True
        assert service.load_snapshot("clean", serial="emu-1", reset_network=False)
        service.adb_fake.reply = ("KO: unknown snapshot\n", "")
        assert service.load_snapshot("gone", serial="emu-1") is False
    assert resets == ["emu-1"]  # once: not for False, not for a failed load


def test_reset_network_after_load_follows_the_setting(monkeypatch):
    from sandroid.services import emulator_service as es

    sent: list[str] = []

    def send(command):
        sent.append(command)
        if "airplane_mode_on" in command:
            return "0\n", ""
        if "Active default network" in command:
            # up, down after the switch, up again
            up = sum("airplane-mode" in c for c in sent) != 1
            return ("Active default network: 100\n" if up else
                    "Active default network: none\n"), ""  # fmt: skip
        return "", ""

    assert es.reset_network_after_load("emu-1", mode="off", send=send) is False
    assert sent == []
    monkeypatch.setattr(es, "network_reset_mode", lambda: "airplane")
    assert es.reset_network_after_load("emu-1", send=send, sleep=lambda s: None)
    assert "shell cmd connectivity airplane-mode enable" in sent
    assert "shell cmd connectivity airplane-mode disable" in sent


def test_a_timed_out_load_is_prepared_once_the_device_answers(service, monkeypatch):
    """N4-B7: the console gave up, the emulator finished the load after a
    pause. The device state is unknown at once (a world change: the header
    shows the device time as unknown, not "in sync"), and when the device
    answers the post-load routine (SELinux, clock sync, Frida) and the
    network reset run.
    """
    from sandroid.core.events import EventBus, EventType
    from sandroid.services import emulator_service as es

    adb = service.adb_fake
    adb.reply = ("", "error: timeout")
    answers = iter(["", "", "ok"])

    def send_adb(command, serial=None):
        adb.order.append(command)
        if command == "shell echo ok":
            return next(answers, "ok") + "\n", ""
        return ("device\n", "") if command == "get-state" else ("", "")

    adb.send_adb_command = send_adb
    service.UNCONFIRMED_LOAD_POLL_S = 0.01
    steps: list = []
    monkeypatch.setattr(
        service, "_post_load", lambda a, name, serial: steps.append(("post", name))
    )
    monkeypatch.setattr(
        es, "reset_network_after_load", lambda serial, **kw: steps.append("network")
    )
    monkeypatch.setattr(es, "is_active_serial", lambda serial: True)
    states: list = []

    def on_state(event):
        if event.data.get("change_type") == "snapshot_state":
            states.append(event.data["state"])

    bus = EventBus.get()
    bus.subscribe(EventType.STATE_CHANGED, on_state)
    try:
        with timeline.capture() as lines:
            assert service.load_snapshot("start", serial="emu-1") is False
            assert _wait(lambda: "network" in steps)
    finally:
        bus.unsubscribe(EventType.STATE_CHANGED, on_state)
    assert steps == [("post", "start"), "network"]
    assert adb.order.count("shell echo ok") == 3
    world = [x for x in lines if x.get("data", {}).get("cause") == "snapshot-load"]
    assert world
    assert world[0]["data"]["unconfirmed"] is True
    assert "device state unknown" in world[0]["summary"]
    assert _wait(lambda: states == ["unconfirmed", "loaded"])


def test_a_refused_load_is_not_watched(service, monkeypatch):
    service.adb_fake.reply = ("KO: unknown snapshot\n", "")
    watched: list = []
    monkeypatch.setattr(
        service, "_watch_unconfirmed_load", lambda *a: watched.append(a)
    )
    with timeline.capture():
        assert service.load_snapshot("gone", serial="emu-1") is False
    assert watched == []
