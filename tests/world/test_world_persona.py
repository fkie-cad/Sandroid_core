"""Persona wiring: a world from an identity profile, persona snapshots saved
and pruned as the ``persona`` actor. No device, no emulator.
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING

import pytest

from sandroid.core import snapshot_policy as sp
from sandroid.services import identity as ident
from sandroid.services.identity import IdentityService
from sandroid.world import PackSet, persona
from sandroid.world import __main__ as cli
from sandroid.world.helper import ShellResult
from sandroid.world.prepare import STAMP_FORMAT

if TYPE_CHECKING:
    from pathlib import Path

PACKS = PackSet(user_dir=False)
SERIAL = "emulator-5998"
AVD = "Persona_Test"

PROFILE = """\
format: sandroid-identity
schema: 2
id: mara
name: Mara (DE)
token: "3f9a1c07"
seed: hex:{seed}
owner:
  first: Mara
  last: Schneider
  phone: "+4915204902863"
  email: "mara.schneider.{{token}}@example.org"
values: {{}}
world:
  seed: auto
  size: small
  country: de
"""


@pytest.fixture
def svc(tmp_path, monkeypatch):
    monkeypatch.setenv(ident.PROFILES_DIR_ENV, str(tmp_path / "profiles"))
    lib = ident.profiles_dir()
    lib.mkdir(parents=True, exist_ok=True)
    (lib / "mara.yaml").write_text(PROFILE.format(seed="11" * 32), encoding="utf-8")
    (lib / "noworld.yaml").write_text(
        PROFILE.format(seed="22" * 32)
        .replace("id: mara", "id: noworld")
        .split("world:")[0],
        encoding="utf-8",
    )
    return IdentityService()


@pytest.fixture
def avd_root(tmp_path, monkeypatch):
    root = tmp_path / "avd" / f"{AVD}.avd"
    (root / "snapshots").mkdir(parents=True)
    from sandroid.core import emulator

    monkeypatch.setattr(emulator, "avd_dir", lambda name: root if name == AVD else None)
    return root


class FakeEmulator:
    """Records saves/deletes and applies the real snapshot policy."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[str, str, str, str | None]] = []
        self.fail_save = False

    def create_snapshot(self, name, serial=None, *, actor=None):
        who = actor or sp.current_actor()[0]
        self.calls.append(("save", name, who, serial))
        if self.fail_save or sp.check("save", name, actor=who, avd=AVD, exists=False):
            return False
        folder = self.root / "snapshots" / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "snapshot.pb").write_bytes(b"pb")
        (folder / "ram.bin").write_bytes(b"ram")
        return True

    def delete_snapshot(self, name, serial=None, *, actor=None, confirmed=None):
        who = actor or sp.current_actor()[0]
        self.calls.append(("delete", name, who, serial))
        if sp.check("delete", name, actor=who, avd=AVD):
            return False
        for f in (self.root / "snapshots" / name).iterdir():
            f.unlink()
        (self.root / "snapshots" / name).rmdir()
        return True


class StampDevice:
    serial = SERIAL

    def __init__(self, stamp: dict | None) -> None:
        self.stamp = stamp

    def shell(self, script, *, timeout=60, zygote=False):
        out = json.dumps(self.stamp) if self.stamp is not None else ""
        return ShellResult(0, out, "")


def _stamp(fp: str, state: str = "complete") -> dict:
    return {"format": STAMP_FORMAT, "state": state, "world_fp": fp}


def _old_persona(root: Path, name: str, age: int) -> None:
    folder = root / "snapshots" / name
    folder.mkdir(parents=True)
    for f in ("snapshot.pb", "ram.bin"):
        (folder / f).write_bytes(b"x")
        t = 1_700_000_000 - age
        os.utime(folder / f, (t, t))


# ------------------------------------------------------------- the manifest


def test_a_profile_world_is_stable_and_its_seed_written_back(svc) -> None:
    first, profile = persona.manifest_for_profile("mara", service=svc, packs=PACKS)
    assert profile.world["seed"].startswith("hex:")
    assert IdentityService().load("mara").world["seed"] == profile.world["seed"]
    again, _ = persona.manifest_for_profile(
        "mara", service=IdentityService(), packs=PACKS
    )
    assert again.world_fp == first.world_fp
    assert first.owner["first"] == "Mara"
    assert first.owner["last"] == "Schneider"


def test_a_profile_without_a_world_is_refused(svc) -> None:
    with pytest.raises(persona.PersonaError, match="no world section"):
        persona.manifest_for_profile("noworld", service=svc, packs=PACKS)


def test_the_persona_name_carries_both_fingerprints(svc) -> None:
    manifest, profile = persona.manifest_for_profile("mara", service=svc, packs=PACKS)
    name = persona.persona_name(profile, manifest)
    assert name.startswith("sandroid_persona_mara_")
    assert manifest.world_fp[:12] in name
    assert ident.fingerprint(profile)[:12] in name
    assert sp.owner_of(name).owner == persona.ACTOR


# ------------------------------------------------------------ the snapshots


def test_save_runs_as_persona_and_prunes_to_keep(avd_root) -> None:
    for i, age in enumerate((10, 20, 30)):
        _old_persona(
            avd_root, f"sandroid_persona_old{i}_aaaaaaaaaaaa_bbbbbbbbbbbb", age
        )
    _old_persona(avd_root, "clean_8g", 5)
    emu = FakeEmulator(avd_root)
    name = "sandroid_persona_mara_111111111111_222222222222"
    out = persona.save_persona_snapshot(
        SERIAL,
        AVD,
        name,
        world_fp="f" * 64,
        keep=3,
        emulator=emu,
        device=StampDevice(_stamp("f" * 64)),
    )
    assert out.saved, out.error
    assert out.pruned == ["sandroid_persona_old2_aaaaaaaaaaaa_bbbbbbbbbbbb"]
    assert out.kept[0] == name
    assert len(out.kept) == 3
    assert {c[2] for c in emu.calls} == {persona.ACTOR}
    assert {c[3] for c in emu.calls} == {SERIAL}
    assert (avd_root / "snapshots" / "clean_8g").is_dir()
    assert persona.persona_snapshots(AVD)[0] == name


@pytest.mark.parametrize(
    ("stamp", "match"),
    [
        (None, "holds no world"),
        (_stamp("e" * 64), "not ffffffffffff"),
        (_stamp("f" * 64, state="seeding"), r"\(seeding\)"),
    ],
)
def test_save_needs_the_complete_world_on_the_device(avd_root, stamp, match) -> None:
    emu = FakeEmulator(avd_root)
    out = persona.save_persona_snapshot(
        SERIAL,
        AVD,
        "sandroid_persona_mara_111111111111_222222222222",
        world_fp="f" * 64,
        emulator=emu,
        device=StampDevice(stamp),
    )
    assert not out.saved
    assert out.error
    assert re.search(match, out.error)
    assert emu.calls == []


def test_only_persona_names_are_saved_or_deleted(avd_root) -> None:
    emu = FakeEmulator(avd_root)
    out = persona.save_persona_snapshot(
        SERIAL,
        AVD,
        "clean_8g",
        world_fp="f" * 64,
        emulator=emu,
        device=StampDevice(_stamp("f" * 64)),
    )
    assert not out.saved
    assert "not a persona snapshot" in out.error
    assert not persona.delete_persona_snapshot(SERIAL, "clean_8g", emulator=emu)
    assert emu.calls == []


def test_a_failed_save_prunes_nothing(avd_root) -> None:
    _old_persona(avd_root, "sandroid_persona_old_aaaaaaaaaaaa_bbbbbbbbbbbb", 10)
    emu = FakeEmulator(avd_root)
    emu.fail_save = True
    out = persona.save_persona_snapshot(
        SERIAL,
        AVD,
        "sandroid_persona_mara_111111111111_222222222222",
        world_fp="f" * 64,
        keep=1,
        emulator=emu,
        device=StampDevice(_stamp("f" * 64)),
    )
    assert not out.saved
    assert out.pruned == []
    assert [c[0] for c in emu.calls] == ["save"]


def test_a_stub_without_ram_is_not_a_persona_snapshot(avd_root) -> None:
    stub = avd_root / "snapshots" / "sandroid_persona_stub_aaaaaaaaaaaa_bbbbbbbbbbbb"
    stub.mkdir()
    (stub / "snapshot.pb").write_bytes(b"pb")
    assert persona.persona_snapshots(AVD) == []


@pytest.mark.parametrize(
    ("world", "keep"),
    [(None, 3), ({}, 3), ({"persona_snapshots": 5}, 5), ({"persona_snapshots": 0}, 1)],
)
def test_keep_comes_from_the_config(monkeypatch, world, keep) -> None:
    from sandroid import config

    class Cfg:
        pass

    cfg = Cfg()
    if world is not None:
        cfg.world = world
    monkeypatch.setattr(config, "get_config", lambda: cfg)
    assert persona.configured_keep() == keep


# --------------------------------------------------------------------- CLI


def test_cli_spec_and_profile_exclude_each_other(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["render", "--spec", "x.yaml", "--profile", "mara"])
    assert "exclude each other" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["render"])
    assert "--spec or --profile" in capsys.readouterr().err


def test_cli_render_from_a_profile(svc, monkeypatch, capsys) -> None:
    real = persona.manifest_for_profile
    monkeypatch.setattr(
        persona,
        "manifest_for_profile",
        lambda pid, **kw: real(pid, service=svc, packs=PACKS, **kw),
    )
    assert (
        cli.main(["render", "--profile", "mara", "--anchor", "2026-11-20T15:00"]) == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["contacts"]


# ------------------------------------------------------------------- build


class _Info:
    def __init__(self, status: str, sim: bool = False, reason: str = "") -> None:
        self.status, self.reason, self.enabled, self.sim_launch = (
            status,
            reason,
            True,
            sim,
        )


class _Plan:
    def __init__(self, infos: dict, restored: bool = False) -> None:
        self.infos = infos
        self.restored = restored


class _Report:
    def to_dict(self) -> dict:
        return {"ok": True}


@pytest.fixture
def build_env(svc, avd_root, monkeypatch):
    from sandroid.core import emulator
    from sandroid.world import prepare as pr

    monkeypatch.setattr(emulator, "avd_name_of", lambda serial: AVD)
    order: list[str] = []
    stamp: dict = {}
    real = persona.manifest_for_profile
    monkeypatch.setattr(
        persona,
        "manifest_for_profile",
        lambda pid, **kw: real(pid, **{**kw, "packs": PACKS}),
    )

    def fake_prepare(serial, manifest, **kw):
        order.append("prepare")
        stamp.update(_stamp(manifest.world_fp))
        return _Report()

    monkeypatch.setattr(pr, "prepare", fake_prepare)
    infos = {"imei": _Info("verified"), "imsi": _Info("failed", sim=True)}

    def fake_apply(serial, allow_restart=None, profile=None, package=None, **kw):
        order.append("apply")
        assert allow_restart is True
        assert kw == {"as_persona": True}
        return _Plan(infos)

    monkeypatch.setattr(svc, "apply", fake_apply)

    class Dev(StampDevice):
        def shell(self, script, *, timeout=60, zygote=False):
            if "getprop" in script:
                return ShellResult(0, "35\n", "")
            return ShellResult(0, json.dumps(stamp) if stamp else "", "")

    return svc, order, infos, Dev(None), FakeEmulator(avd_root)


def test_build_prepares_applies_saves_then_is_cached(build_env) -> None:
    svc, order, _infos, dev, emu = build_env
    out = persona.build_persona(SERIAL, "mara", identity=svc, emulator=emu, device=dev)
    assert order == ["prepare", "apply"]
    assert out.save is not None
    assert out.save.saved
    assert out.snapshot in persona.persona_snapshots(AVD)
    assert out.identity["imsi"]["status"] == "failed"  # a SIM value never blocks
    again = persona.build_persona(
        SERIAL, "mara", identity=svc, emulator=emu, device=dev
    )
    assert again.cached
    assert again.snapshot == out.snapshot
    assert order == ["prepare", "apply"]


def test_a_failed_identity_value_saves_nothing(build_env) -> None:
    svc, order, infos, dev, emu = build_env
    infos["gaid"] = _Info("failed")
    with pytest.raises(persona.PersonaError, match="gaid"):
        persona.build_persona(SERIAL, "mara", identity=svc, emulator=emu, device=dev)
    assert emu.calls == []


# ------------------------------------------------------------------- stage


def test_the_persona_stage_is_registered_before_identity() -> None:
    from sandroid.core import device_prep

    names = [(s.name, s.order) for s in device_prep._STAGES]
    assert ("persona", 10) in names
    assert names.index(("persona", 10)) < [n for n, _o in names].index("identity")


@pytest.fixture
def stage_env(svc, avd_root, monkeypatch):
    from sandroid.core import emulator

    meta: dict = {"persona_id": "mara"}
    record: dict = {
        "launch_id": "L1",
        "options": {"boot": "snapshot", "snapshot": "clean_8g"},
        "meta": meta,
    }
    monkeypatch.setattr(
        emulator, "launch_record", lambda serial: record if meta else None
    )
    monkeypatch.setattr(persona, "_BUILT_LAUNCHES", set())
    real = persona.manifest_for_profile
    monkeypatch.setattr(
        persona,
        "manifest_for_profile",
        lambda pid, **kw: real(pid, **{**kw, "service": svc, "packs": PACKS}),
    )
    monkeypatch.setattr(persona, "_device_profile_id", lambda serial: "mara")
    monkeypatch.setattr(persona, "topup_enabled", lambda: False)
    stamp: dict = {}

    class Dev(StampDevice):
        def __init__(self, serial: str) -> None:
            super().__init__(None)

        def shell(self, script, *, timeout=60, zygote=False):
            if "getprop" in script:
                return ShellResult(0, "35\n", "")
            return ShellResult(0, json.dumps(stamp) if stamp else "", "")

    monkeypatch.setattr(persona, "Device", Dev)
    return meta, stamp, record


def test_no_persona_launch_is_silent(stage_env) -> None:
    meta, _stamp, _record = stage_env
    meta.clear()
    assert persona.persona_stage(SERIAL, True, 120.0) is None


def test_a_loaded_persona_is_info(stage_env, svc, avd_root) -> None:
    _meta, stamp, record = stage_env
    record["avd"] = AVD
    manifest, profile = persona.manifest_for_profile("mara", target_sdk=35)
    stamp.update(_stamp(manifest.world_fp))
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "warning"  # the world, but no snapshot of it
    assert "no persona snapshot" in note.text
    _old_persona(avd_root, persona.persona_name(profile, manifest), 1)
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "info"
    assert manifest.world_fp[:12] in note.text


def test_an_interrupted_prepare_of_the_same_world_says_so(stage_env) -> None:
    _meta, stamp, _record = stage_env
    manifest, _ = persona.manifest_for_profile("mara", target_sdk=35)
    stamp.update(_stamp(manifest.world_fp, state="seeding"))
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "warning"
    assert "--force-cleanup" in note.text


def test_a_save_also_removes_persona_stubs(avd_root) -> None:
    stub = avd_root / "snapshots" / "sandroid_persona_stub_aaaaaaaaaaaa_bbbbbbbbbbbb"
    stub.mkdir()
    (stub / "snapshot.pb").write_bytes(b"pb")
    emu = FakeEmulator(avd_root)
    out = persona.save_persona_snapshot(
        SERIAL,
        AVD,
        "sandroid_persona_mara_111111111111_222222222222",
        world_fp="f" * 64,
        emulator=emu,
        device=StampDevice(_stamp("f" * 64)),
    )
    assert out.saved
    assert stub.name in out.pruned
    assert not stub.exists()


def test_another_world_is_left_alone(stage_env, monkeypatch) -> None:
    _meta, stamp, _record = stage_env
    stamp.update(_stamp("e" * 64))
    monkeypatch.setattr(persona, "build_persona", pytest.fail)
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "warning"
    assert "another world (eeeeeeeeeeee" in note.text


def test_missing_photos_are_named_not_downloaded(stage_env, monkeypatch) -> None:
    from sandroid.world import photos

    seen = {}

    def fake_ensure(entries, cache_dir=None, **kw):
        seen.update(kw)
        out = photos.PhotoFetch()
        out.failed = {e["id"]: "not in the cache" for e in entries}
        return out

    monkeypatch.setattr(photos, "ensure_photos", fake_ensure)
    monkeypatch.setattr(persona, "build_persona", pytest.fail)
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert seen == {"download": False}
    assert note.level == "warning"
    assert "photos fetch --profile mara" in note.text


def test_a_clean_base_is_built_and_saved(stage_env, monkeypatch) -> None:
    from sandroid.world import photos

    monkeypatch.setattr(
        photos,
        "ensure_photos",
        lambda entries, cache_dir=None, **kw: photos.PhotoFetch(),
    )
    calls: list = []
    monkeypatch.setattr(persona, "build_persona", _fake_build(calls))
    monkeypatch.setattr(persona, "_device_profile_id", lambda serial: "other")
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert [c[:3] for c in calls] == [(SERIAL, "mara", True)]
    assert "saved as sandroid_persona_mara_x" in note.text
    assert note.level == "warning"  # the identity stage applies another profile
    assert "applies other, not mara" in note.text


def _fake_build(calls: list):
    def fake_build(serial, pid, **kw):
        calls.append((serial, pid, kw.get("rebuild"), kw.get("deadline")))
        return persona.PersonaBuild(
            profile=pid,
            snapshot="sandroid_persona_mara_x",
            save=persona.PersonaSave(name="sandroid_persona_mara_x", saved=True),
        )

    return fake_build


@pytest.mark.parametrize(
    "options",
    [
        {"boot": "normal", "snapshot": None},
        {"boot": "snapshot", "snapshot": "sandroid_persona_mara_x"},
        {"boot": "cold", "snapshot": None},
    ],
)
def test_no_world_outside_a_base_launch_is_only_a_warning(
    stage_env, monkeypatch, options
) -> None:
    _meta, _stamp, record = stage_env
    record["options"] = options
    monkeypatch.setattr(persona, "build_persona", pytest.fail)
    note = persona.persona_stage(SERIAL, True, 300.0)
    assert note.level == "warning"
    assert "did not start from the clean base" in note.text


def test_a_launch_is_built_once_and_a_named_base_counts(stage_env, monkeypatch) -> None:
    from sandroid.world import photos

    meta, _stamp, record = stage_env
    meta["persona_base"] = "my_base"
    record["options"] = {"boot": "snapshot", "snapshot": "my_base"}
    monkeypatch.setattr(
        photos,
        "ensure_photos",
        lambda entries, cache_dir=None, **kw: photos.PhotoFetch(),
    )
    calls: list = []
    monkeypatch.setattr(persona, "build_persona", _fake_build(calls))
    first = persona.persona_stage(SERIAL, True, 300.0)
    assert first.level == "info"
    assert len(calls) == 1
    assert calls[0][3] is not None  # a deadline goes down
    second = persona.persona_stage(SERIAL, False, 300.0)  # a rewind, same launch
    assert len(calls) == 1
    assert second.level == "warning"


def test_out_of_time_skips_apply_and_save(build_env) -> None:
    import time

    svc, order, _infos, dev, emu = build_env
    with pytest.raises(persona.PersonaError, match="out of time before the identity"):
        persona.build_persona(
            SERIAL,
            "mara",
            identity=svc,
            emulator=emu,
            device=dev,
            deadline=time.monotonic() + 5,
        )
    assert order == ["prepare"]
    assert emu.calls == []


@pytest.mark.parametrize(
    ("info", "blocks"),
    [
        (_Info("pending", reason="needs a framework restart"), True),
        (_Info("pending", reason="not restarted"), True),
        (_Info("verified", reason=ident.READBACK_NO_ANSWER), True),
        (_Info("applied", reason=ident.READBACK_NO_ANSWER + " (x)"), True),
        (_Info("pending", reason=ident.RESTORED_DURING), True),
        (_Info("pending", reason="no target app yet"), False),
        (_Info("hook-only"), False),
        (_Info("skipped"), False),
    ],
)
def test_what_blocks_a_persona_save(info, blocks) -> None:
    assert persona._unbaked({"x": info}) == (["x"] if blocks else [])


@pytest.mark.parametrize("meta", [None, {}, {"persona": "old-key"}, {"persona_id": ""}])
def test_the_core_wrapper_skips_non_persona_launches(monkeypatch, meta) -> None:
    from sandroid.core import device_prep, emulator

    monkeypatch.setattr(
        emulator,
        "launch_record",
        lambda serial: None if meta is None else {"meta": meta},
    )
    monkeypatch.setattr(persona, "persona_stage", pytest.fail)
    assert device_prep._persona_stage(SERIAL, True, 300.0) is None


def test_a_refused_identity_apply_is_a_persona_error(build_env, monkeypatch) -> None:
    svc, _order, _infos, dev, emu = build_env

    def refuse(serial, **kw):
        raise ident.IdentityApplyError("the identity record cannot be read")

    monkeypatch.setattr(svc, "apply", refuse)
    with pytest.raises(persona.PersonaError, match="identity apply refused"):
        persona.build_persona(SERIAL, "mara", identity=svc, emulator=emu, device=dev)
    assert emu.calls == []


def test_the_device_profile_comes_from_the_identity_service(monkeypatch) -> None:
    from sandroid.services import identity

    class Svc:
        def profile_id_for(self, serial):
            return f"p-{serial}"

    monkeypatch.setattr(identity, "get_identity_service", lambda: Svc())
    assert persona._device_profile_id(SERIAL) == f"p-{SERIAL}"


def test_a_restore_during_the_apply_saves_nothing(build_env, monkeypatch) -> None:
    svc, _order, infos, dev, emu = build_env
    monkeypatch.setattr(svc, "apply", lambda serial, **kw: _Plan(infos, restored=True))
    with pytest.raises(persona.PersonaError, match="restored during the identity"):
        persona.build_persona(SERIAL, "mara", identity=svc, emulator=emu, device=dev)
    assert emu.calls == []


# ------------------------------------------------------------ top-up on load


def test_a_loaded_persona_is_topped_up_and_says_so(
    stage_env, avd_root, monkeypatch
) -> None:
    from sandroid.core import timeline
    from sandroid.world import prepare as pr

    _meta, stamp, record = stage_env
    record["avd"] = AVD
    manifest, profile = persona.manifest_for_profile("mara", target_sdk=35)
    stamp.update(_stamp(manifest.world_fp))
    _old_persona(avd_root, persona.persona_name(profile, manifest), 1)
    calls: list = []

    def fake_topup(serial, manifest, **kw):
        calls.append((serial, manifest.world_fp))
        return pr.TopUpReport(
            serial=serial, ran=True, counts={"sms": 3, "calls": 2, "events": 0}
        )

    lines: list = []

    class TL:
        def emit(self, src, kind, **kw):
            lines.append((src, kind, kw))

    monkeypatch.setattr(pr, "topup", fake_topup)
    monkeypatch.setattr(timeline, "get_timeline", lambda: TL())
    monkeypatch.setattr(persona, "topup_enabled", lambda: True)
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "info"
    assert "topped up with 3 SMS, 2 calls" in note.text
    assert calls == [(SERIAL, manifest.world_fp)]
    assert [(s, k) for s, k, _kw in lines] == [("device", "persona_topup")]
    assert lines[0][2]["data"]["counts"]["sms"] == 3


def test_a_failed_topup_is_a_warning_in_words(stage_env, avd_root, monkeypatch) -> None:
    from sandroid.world import prepare as pr

    _meta, stamp, record = stage_env
    record["avd"] = AVD
    manifest, profile = persona.manifest_for_profile("mara", target_sdk=35)
    stamp.update(_stamp(manifest.world_fp))
    _old_persona(avd_root, persona.persona_name(profile, manifest), 1)

    def boom(serial, manifest, **kw):
        raise pr.PrepareError("the top-up needs adb root (adb root)")

    monkeypatch.setattr(pr, "topup", boom)
    monkeypatch.setattr(persona, "topup_enabled", lambda: True)
    note = persona.persona_stage(SERIAL, True, 120.0)
    assert note.level == "warning"
    assert "top-up failed: the top-up needs adb root" in note.text


@pytest.mark.parametrize(
    ("world", "on"),
    [(None, True), ({}, True), ({"persona_topup": False}, False),
     ({"persona_topup": "no"}, True), ({"persona_topup": True}, True)],
)  # fmt: skip
def test_the_topup_follows_the_config(monkeypatch, world, on) -> None:
    from types import SimpleNamespace

    from sandroid import config

    monkeypatch.setattr(config, "get_config", lambda: SimpleNamespace(world=world))
    assert persona.topup_enabled() is on
    if not on:
        assert persona.after_load_topup(SERIAL, object()) == ("", False)


# ------------------------------------------------------ start as a persona


def test_persona_choices_list_world_profiles_and_their_snapshots(svc, avd_root) -> None:
    _old_persona(avd_root, "sandroid_persona_mara_aaaaaaaaaaaa_bbbbbbbbbbbb", 1)
    _old_persona(avd_root, "sandroid_persona_other_aaaaaaaaaaaa_bbbbbbbbbbbb", 2)
    choices = persona.persona_choices(AVD, service=svc)
    assert [(c.id, c.snapshots) for c in choices] == [("mara", 1)]
    assert choices[0].name == "Mara (DE)"


def test_persona_start_loads_its_snapshot_else_the_base(svc, avd_root) -> None:
    with pytest.raises(persona.PersonaError, match="no clean_8g"):
        persona.persona_start(AVD, "mara", api=35, service=svc)
    base = avd_root / "snapshots" / "clean_8g"
    base.mkdir()
    (base / "ram.bin").write_bytes(b"x")
    first = persona.persona_start(AVD, "mara", api=35, headless=True, service=svc)
    assert not first.cached
    assert first.options.boot == "snapshot"
    assert first.options.snapshot == "clean_8g"
    assert first.options.save_on_exit is False
    assert first.options.headless is True
    assert first.meta == {"persona_id": "mara"}
    _old_persona(avd_root, first.snapshot, 1)
    again = persona.persona_start(AVD, "mara", api=35, service=svc)
    assert again.cached
    assert again.options.snapshot == first.snapshot == again.snapshot
    assert again.meta == {"persona_id": "mara"}
    other = persona.persona_start(AVD, "mara", api=35, base="mybase", service=svc)
    assert other.meta == {"persona_id": "mara", "persona_base": "mybase"}


# ------------------------------------------------------------------ refresh


@pytest.fixture
def refresh_env(build_env, monkeypatch):
    from sandroid.world import prepare as pr

    svc, order, _infos, _dev, emu = build_env
    stamp_box: dict = {}

    class _Refreshed:
        def to_dict(self):
            return {"ok": True, "changes": {"added": {"sms": 2}, "removed": {"sms": 1}}}

    def fake_refresh(serial, manifest, **kw):
        order.append("refresh")
        stamp_box.update(_stamp(manifest.world_fp))
        return _Refreshed()

    class Dev(StampDevice):
        def shell(self, script, *, timeout=60, zygote=False):
            if "getprop" in script:
                return ShellResult(0, "35\n", "")
            return ShellResult(0, json.dumps(stamp_box) if stamp_box else "", "")

    monkeypatch.setattr(pr, "refresh", fake_refresh)
    tops: list = []

    def fake_topup(serial, manifest, device=None):
        tops.append(serial)
        return "topped up with 1 SMS", False

    monkeypatch.setattr(persona, "after_load_topup", fake_topup)
    return svc, order, Dev(None), emu, stamp_box, tops


def test_refresh_does_nothing_when_world_and_identity_are_current(refresh_env) -> None:
    svc, order, dev, emu, stamp, _tops = refresh_env
    manifest, profile = persona.manifest_for_profile("mara", service=svc, target_sdk=35)
    stamp.update(_stamp(manifest.world_fp))
    _old_persona(emu.root, persona.persona_name(profile, manifest), 1)
    out = persona.refresh_persona(
        SERIAL, "mara", identity=svc, emulator=emu, device=dev
    )
    assert out.up_to_date
    assert order == []
    assert emu.calls == []
    assert "up to date" in out.words()


def test_refresh_of_the_identity_only_applies_and_saves(refresh_env) -> None:
    svc, order, dev, emu, stamp, tops = refresh_env
    manifest, _profile = persona.manifest_for_profile(
        "mara", service=svc, target_sdk=35
    )
    stamp.update(_stamp(manifest.world_fp))  # same world, no snapshot of it
    out = persona.refresh_persona(
        SERIAL, "mara", identity=svc, emulator=emu, device=dev
    )
    assert order == ["apply"]  # no world refresh
    assert out.save is not None
    assert out.save.saved
    assert out.snapshot in persona.persona_snapshots(AVD)
    assert not out.world_changed
    assert tops == []
    assert "phone contents unchanged" in out.words()


def test_refresh_of_a_changed_world_is_incremental_then_saved(refresh_env) -> None:
    svc, order, dev, emu, stamp, tops = refresh_env
    stamp.update(_stamp("0" * 64))  # the device holds an older world
    out = persona.refresh_persona(
        SERIAL, "mara", identity=svc, emulator=emu, device=dev
    )
    assert order == ["refresh", "apply"]
    assert out.world_changed
    assert out.save is not None
    assert out.save.saved
    assert emu.calls[0][:3] == ("save", out.snapshot, "persona")
    assert tops == [SERIAL]
    words = out.words()
    assert "2 added, 1 removed" in words
    assert "topped up with 1 SMS" in words


def test_refresh_needs_a_world_on_the_device(refresh_env) -> None:
    svc, _order, dev, emu, _stamp, _tops = refresh_env
    with pytest.raises(persona.PersonaError, match="no complete world"):
        persona.refresh_persona(SERIAL, "mara", identity=svc, emulator=emu, device=dev)
