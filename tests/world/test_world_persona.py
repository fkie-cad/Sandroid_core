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
    def __init__(self, status: str, sim: bool = False) -> None:
        self.status, self.reason, self.enabled, self.sim_launch = status, "", True, sim


class _Plan:
    def __init__(self, infos: dict) -> None:
        self.infos = infos


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

    def fake_apply(serial, allow_restart=None, profile=None, package=None):
        order.append("apply")
        assert allow_restart is True
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
