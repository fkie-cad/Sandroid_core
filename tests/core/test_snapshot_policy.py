"""Snapshot protection: pinned names, owned names, the actor, vanished pins."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sandroid.core import emulator
from sandroid.core import snapshot_policy as policy

if TYPE_CHECKING:
    from pathlib import Path

REC = "sandroid_rec_20261120_101500"


@pytest.fixture(autouse=True)
def prefs(monkeypatch, tmp_path):
    """Isolated devices.json and AVD folders under tmp_path."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    avds = tmp_path / "avds"

    def avd_dir(name):
        path = avds / f"{name}.avd"
        return path if path.is_dir() else None

    monkeypatch.setattr(emulator, "avd_dir", avd_dir)
    return avds


def _snapshot(avds: Path, avd: str, name: str, *, ram: bool = True) -> None:
    path = avds / f"{avd}.avd" / "snapshots" / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "snapshot.pb").write_bytes(b"pb")
    if ram:
        (path / "ram.bin").write_bytes(b"ram")


# -- the rules -----------------------------------------------------------------


def test_loads_are_never_refused():
    assert policy.check("load", "clean_8g", actor="ai") is None
    assert policy.check("load", REC, actor="ai") is None


@pytest.mark.parametrize("actor", ["user", "ai", "rewind"])
def test_pinned_names_are_never_overwritten_or_deleted(actor):
    for op in ("save", "delete"):
        refusal = policy.check(op, "clean_8g", actor=actor, avd="Dev", exists=True)
        assert refusal is not None
        assert refusal.pinned
        assert not refusal.confirmable
        assert "Devices screen" in refusal.reason
    # Confirming does not help either.
    assert policy.check("delete", "default_boot", confirmed=True) is not None


def test_a_pinned_name_that_does_not_exist_yet_may_be_saved():
    assert policy.check("save", "clean_8g", avd="Dev", exists=False) is None
    # Unknown existence counts as existing.
    assert policy.check("save", "clean_8g", avd="Dev", exists=None) is not None


def test_owned_names_belong_to_their_owner():
    assert policy.check("save", REC, actor="rewind", exists=False) is None
    assert policy.check("delete", REC, actor="rewind") is None
    for actor in ("user", "ai", "persona"):
        assert policy.check("save", REC, actor=actor, exists=False) is not None


def test_the_user_may_delete_an_owned_name_after_a_confirm():
    refusal = policy.check("delete", REC, actor="user")
    assert refusal is not None
    assert refusal.confirmable
    assert refusal.owner == "rewind"
    assert "Rewind start point" in refusal.reason
    assert policy.check("delete", REC, actor="user", confirmed=True) is None


def test_the_ai_never_deletes_an_owned_name_even_confirmed():
    refusal = policy.check("delete", REC, actor="ai", confirmed=True)
    assert refusal is not None
    assert not refusal.confirmable


def test_rewind_names_use_rewind_s_own_check():
    # Only real start point names, not anything with the prefix.
    assert policy.owner_of("sandroid_rec_my_backup") is None
    assert policy.owner_of(REC).owner == "rewind"
    assert policy.owner_of("sandroid_persona_ab12cd34_ef56ab78").owner == "persona"
    assert policy.owner_of("sandroid_malware_20261120_101500").owner == "analysis"
    assert policy.owner_of("tmp") is None


def test_everything_else_is_open_to_everyone():
    for actor in ("user", "ai"):
        assert policy.check("save", "tmp", actor=actor, exists=True) is None
        assert policy.check("delete", "tmp", actor=actor) is None


def test_a_registered_namespace_can_be_replaced_and_removed():
    space = policy.Namespace("demo", "demo snapshot", lambda n: n.startswith("d_"))
    policy.register_namespace(space)
    try:
        assert policy.check("delete", "d_1", actor="ai") is not None
    finally:
        policy.unregister_namespace("demo")
    assert policy.check("delete", "d_1", actor="ai") is None


def test_acting_as_sets_the_actor_for_the_block():
    assert policy.current_actor() == ("user", False)
    with policy.acting_as("rewind"):
        assert policy.current_actor() == ("rewind", False)
        with policy.acting_as("user", confirmed=True):
            assert policy.current_actor() == ("user", True)
    assert policy.current_actor() == ("user", False)


# -- pins -----------------------------------------------------------------------


def test_default_pins_until_the_user_changes_them():
    assert policy.pinned("Dev") == {"clean_8g", "default_boot"}
    assert policy.pinned(None) == {"clean_8g", "default_boot"}
    policy.unpin("Dev", "default_boot")
    policy.pin("Dev", "golden")
    assert policy.pinned("Dev") == {"clean_8g", "golden"}
    assert policy.pinned("Other") == {"clean_8g", "default_boot"}
    assert policy.check("delete", "default_boot", avd="Dev") is None
    assert policy.check("delete", "golden", avd="Dev") is not None


def test_remembering_launch_options_keeps_the_pins():
    policy.pin("Dev", "golden")
    emulator.remember_launch("Dev", emulator.AvdLaunchOptions(headless=True))
    assert "golden" in policy.pinned("Dev")


def test_a_vanished_pinned_snapshot_is_reported_once(prefs):
    _snapshot(prefs, "Dev", "clean_8g")
    assert policy.vanished_pins("Dev", ["clean_8g", "tmp"]) == []
    assert policy.vanished_pins("Dev", ["tmp"]) == ["clean_8g"]
    assert policy.vanished_pins("Dev", ["tmp"]) == []  # once
    # A pin never seen on disk is not "gone"; an unpinned one is not watched.
    assert policy.vanished_pins("Dev", []) == []
    policy.unpin("Dev", "clean_8g")
    assert policy.vanished_pins("Dev", ["clean_8g"]) == []
    assert policy.vanished_pins("Dev", []) == []


def test_snapshot_complete_needs_the_ram_image(prefs):
    _snapshot(prefs, "Dev", "full")
    _snapshot(prefs, "Dev", "stub", ram=False)
    assert policy.snapshot_complete("Dev", "full")
    assert not policy.snapshot_complete("Dev", "stub")
    assert policy.snapshot_exists("Dev", "stub")
    assert policy.snapshot_exists("Dev", "missing") is False
    assert policy.snapshot_exists("Nope", "x") is None


# -- enforced at the service ----------------------------------------------------


class _Adb:
    def __init__(self) -> None:
        self.telnet: list[str] = []

    def send_telnet_command(self, command, serial=None):
        self.telnet.append(command)
        return "OK\n", ""

    def send_adb_command(self, command, serial=None):
        if command == "emu avd name":
            return "Dev\nOK\n", ""
        return "", ""

    def get_target_device(self):
        return "emulator-5554"


@pytest.fixture
def service(prefs):
    from sandroid.services.emulator_service import EmulatorService

    svc = EmulatorService()
    adb = _Adb()
    svc._get_adb = lambda: adb
    svc.adb_fake = adb
    _snapshot(prefs, "Dev", "clean_8g")
    _snapshot(prefs, "Dev", REC)
    return svc


def test_the_service_refuses_before_any_console_call(service):
    assert service.create_snapshot("clean_8g") is False
    assert service.delete_snapshot("clean_8g") is False
    with policy.acting_as("ai"):
        assert service.delete_snapshot(REC) is False
    assert service.adb_fake.telnet == []
    assert service.snapshot_refusal("delete", "clean_8g").pinned


def test_the_service_lets_owners_and_confirmed_users_through(service):
    with policy.acting_as("rewind"):
        assert service.delete_snapshot(REC) is True
    assert service.delete_snapshot(REC, actor="user", confirmed=True) is True
    assert service.create_snapshot("tmp") is True
    assert service.adb_fake.telnet == [
        f"avd snapshot del {REC}",
        f"avd snapshot del {REC}",
        "avd snapshot save tmp",
    ]


def test_a_refused_save_is_a_timeline_warning(service):
    from sandroid.core import timeline

    with timeline.capture() as lines:
        assert service.create_snapshot("clean_8g") is False
    (line,) = lines
    assert (line["src"], line["kind"], line["level"]) == ("snapshot", "save", "warn")
    assert line["data"]["error"].startswith("refused: ")


def test_the_ai_tool_says_why_it_was_refused(service, monkeypatch):
    from sandroid.ai.tools import environment_control as tools

    monkeypatch.setattr(tools, "_require_emulator_device", lambda: None)
    monkeypatch.setattr("sandroid.services.get_emulator_service", lambda: service)
    result = tools.delete_snapshot("clean_8g")
    assert result["deleted"] is False
    assert "pinned" in result["refused"]
    assert service.adb_fake.telnet == []
