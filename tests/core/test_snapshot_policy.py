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
    # A stub holds nothing to protect: it does not count as existing.
    assert policy.snapshot_exists("Dev", "full")
    assert policy.snapshot_exists("Dev", "stub") is False
    assert policy.snapshot_exists("Dev", "missing") is False
    assert policy.snapshot_exists("Nope", "x") is None


def test_an_unknown_avd_protects_every_avd_s_pins():
    policy.pin("Dev", "golden")
    assert policy.pinned(None) >= {"clean_8g", "default_boot", "golden"}
    assert policy.check("delete", "golden", avd=None) is not None
    assert policy.check("delete", "golden", avd="Other") is None


def test_pins_alone_are_no_remembered_launch_options(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        emulator, "_config_emulator", lambda: SimpleNamespace(avd_headless=True)
    )
    policy.pin("Dev", "golden")
    policy.vanished_pins("Other", ["default_boot"])
    for avd in ("Dev", "Other"):
        assert emulator.remembered_options(avd).headless is True


def test_rewind_and_analysis_save_and_delete_as_themselves(monkeypatch):
    from types import SimpleNamespace

    from sandroid.analysis.snapshot_manager import SnapshotManager
    from sandroid.tui.controllers.recording_controller import RecordingController

    seen = []

    def record(kind):
        def call(*args, **kwargs):
            seen.append((kind, policy.current_actor()[0]))
            return True

        return call

    toolbox = SimpleNamespace(
        create_snapshot=record("save"), delete_snapshot=record("delete")
    )
    manager = SnapshotManager()
    assert manager._save_snapshot(toolbox, "sandroid_malware")
    assert manager.discard_snapshot(toolbox)
    service = SimpleNamespace(
        list_snapshots=lambda: [SimpleNamespace(name=REC)],
        delete_snapshot=record("delete"),
    )
    monkeypatch.setattr("sandroid.services.get_emulator_service", lambda: service)
    assert RecordingController._reap_start_point(REC, "emulator-5554", wait_s=1.0)
    assert seen == [
        ("save", "analysis"),
        ("delete", "analysis"),
        ("delete", "rewind"),
    ]


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


# -- snapshot.pb (read only) ------------------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _field(no: int, value: int | str | bytes) -> bytes:
    if isinstance(value, int):
        return _varint(no << 3) + _varint(value)
    data = value.encode() if isinstance(value, str) else value
    return _varint(no << 3 | 2) + _varint(len(data)) + data


def _pb(*, reason: int = 0, build: str = "13025442", loads: int = 3) -> bytes:
    """A snapshot.pb like the emulator writes: images, host, config and
    launch parameters (nested and repeated fields) around the scalars.
    """
    image = _field(2, "/sdk/system-images/android-35/system.img") + _field(3, 1)
    parts = [
        _field(1, 84079),
        _field(2, 1795124175),
        _field(3, image),
        _field(3, _field(2, "")),
        _field(4, b""),
        _field(5, _field(1, 7) + _field(4, 8 << 30)),
        _field(10, 0),
        _field(11, loads),
        _field(17, "-feature"),
        _field(17, "port"),
        _field(19, "AE3A.240806.036 dev-keys"),
        b"\x29" + (1).to_bytes(8, "little"),  # field 5, fixed64 (skipped)
    ]
    if reason:
        parts.insert(5, _field(7, reason))
    if build:
        parts.append(_field(18, build))
    return b"".join(parts)


def test_snapshot_pb_scalars_are_decoded_and_the_rest_skipped():
    info = policy.parse_snapshot_pb(_pb(reason=10005, loads=6))
    assert info.version == 84079
    assert info.created == 1795124175
    assert info.failed_reason == 10005
    assert info.successful_loads == 6
    assert info.emulator_build == "13025442"
    assert info.system_image_build == "AE3A.240806.036 dev-keys"
    assert policy.parse_snapshot_pb(b"") == policy.SnapshotPb()
    for bad in (b"\x0a\x05ab", b"\x08", b"\x0f\x01", b"\x00\x01"):
        with pytest.raises(ValueError):
            policy.parse_snapshot_pb(bad)


@pytest.mark.parametrize(
    ("kw", "words"),
    [
        ({}, ""),
        ({"reason": 4}, "will not load (saved by an incompatible emulator version)"),
        ({"reason": 10005}, "a load failed before (AVD configuration changed)"),
        ({"reason": 99}, "will not load (reason code 99)"),
        ({"build": "14214601"}, "last written by emulator build 14214601, not "
         "emulator 35.4.9 (build 13025442)"),
        ({"build": ""}, ""),
    ],
)  # fmt: skip
def test_snapshot_pb_warnings_in_words(kw, words):
    info = policy.parse_snapshot_pb(_pb(**kw))
    text = policy.snapshot_pb_warning(
        info, installed_version="35.4.9", installed_build="13025442"
    )
    assert (words in text) if words else text == ""
    assert not any(g in text for g in "✓✗▸⇧␣⏎←→")


def test_snapshot_pb_warning_names_the_running_emulators_build():
    info = policy.parse_snapshot_pb(_pb(build="13025442"))
    text = policy.snapshot_pb_warning(
        info,
        installed_version="35.4.9",
        installed_build="13025442",
        launch_build="14214601",
    )
    assert text == ""  # the installed build wrote it: fine
    info = policy.parse_snapshot_pb(_pb(build="99"))
    text = policy.snapshot_pb_warning(
        info, installed_build="13025442", launch_build="14214601"
    )
    assert "the running emulator (build 14214601)" in text
    assert policy.snapshot_pb_warning(None) == ""


def test_snapshot_warnings_read_the_files_and_never_write_them(prefs):
    import os

    _snapshot(prefs, "Dev", "clean_8g")
    _snapshot(prefs, "Dev", "sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb")
    _snapshot(prefs, "Dev", "broken")
    folder = prefs / "Dev.avd" / "snapshots"
    (folder / "clean_8g" / "snapshot.pb").write_bytes(_pb())
    (
        folder / "sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb" / "snapshot.pb"
    ).write_bytes(_pb(reason=4, build="14214601"))
    (folder / "broken" / "snapshot.pb").write_bytes(b"\xff\xff")
    stamps = {
        p: (p.read_bytes(), p.stat().st_mtime_ns) for p in folder.glob("*/snapshot.pb")
    }
    found = policy.snapshot_warnings(
        "Dev",
        [
            "clean_8g",
            "sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb",
            "broken",
            "gone",
        ],
        installed=("35.4.9", "13025442"),
    )
    assert list(found) == ["sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb"]
    text = found["sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb"]
    assert text.startswith("will not load")
    assert "build 14214601" in text
    for p, (data, mtime) in stamps.items():
        assert p.read_bytes() == data
        assert p.stat().st_mtime_ns == mtime
    assert policy.snapshot_warnings("Nope", ["clean_8g"]) == {}
