"""Emulator SIM identity (``services/identity_sim.py``): encodings, the
modem simulator file patches, the private sysdir and the launch hooks.
No emulator, no adb: a fake system image directory under ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from sandroid.core import emulator
from sandroid.services import identity as ident
from sandroid.services import identity_sim as sim
from sandroid.services.identity_sim import SimValues

# A trimmed copy of the stock iccprofile_for_sim0.xml (emulator 35.4.9, every
# API 31-36 image ships the same file), with its odd indentation and the
# EF_MBDN header that names 6F40 too.
TEMPLATE = """<IccProfile>
    <MF path="3F00">
        <EF name="EF_ICCID" id="2FE2" structure="transparent">
            <SIMIO cmd="C0" p1="0" p2="0" p3="F" data="">144,0,62178202412183022FE28A01058B032F06038002000A880110</SIMIO>
            <SIMIO cmd="B0" p1="0" p2="0" p3="A" data="">144,0,98683081462002318379</SIMIO>
            <!-- Special ATC to read ICCID from modem cache -->
            <CCID>89860318640220133897</CCID>
        </EF>
        <EF name="EF_PL" id="2F05" structure="transparent">
            <SIMIO cmd="B0" p1="0" p2="0" p3="4" data="">144,0,FFFFFFFF</SIMIO>
        </EF>

        <ADF name="USIM" path="7FFF" aid="A0000000871002FF86FF0389FFFFFFFF">
            <EF name="EF_IMSI" id="6F07" structure="transparent">
                <CIMI>310260000000000</CIMI>
            </EF>
            <EF name="EF_MSISDN" id="6F40" structure="linear fixed">
                <SIMIO cmd="C0" p1="0" p2="0" p3="F" data="">144,0,621982054221001C0283026F408A01058B036F0605800200388800</SIMIO>
            <SIMIO cmd="B2" p1="1" p2="4" p3="1C" data="">144,0,000000000000000000000000000007915155214365F7FFFFFFFFFFFF</SIMIO>
            </EF>
        <EF name="EF_MBDN" id="6FC7" structure="linear fixed">
            <SIMIO cmd="C0" p1="0" p2="0" p3="F" data="">144,0,621982054221001C0283026F408A01058B036F06058002003E8800</SIMIO>
            <SIMIO cmd="B2" p1="1" p2="4" p3="1C" data="">144,0,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF07915155674523F1FFFFFFFFFFFF</SIMIO>
            </EF>
            <EF name="EF_AD" id="6FAD" structure="transparent">
                <SIMIO cmd="C0" p1="0" p2="0" p3="F" data="">144,0,62178202412183026FAD8A01058B036F060180020004880118</SIMIO>
            <SIMIO cmd="B0" p1="0" p2="0" p3="4" data="">144,0,00000003</SIMIO>
            </EF>
        </ADF>
    </MF>
</IccProfile>
"""

NUMERIC = """<?xml version="1.0" encoding="utf-8"?>
<resources xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
    <add-resource name="numeric_to_operator" type="array"/>
    <string-array name="numeric_to_operator">
        <item numeric="310260">T-Mobile=TMOBILE</item>
    </string-array>
</resources>
"""

#: Verified on the emulator (cold boot, readout +4915112345678).
MSISDN_RECORD = "FFFFFFFFFFFFFFFFFFFFFFFFFFFF0891945111325476F8FFFFFFFFFF"
VALUES = SimValues(
    iccid="8949012345678901234",
    imsi="262019876543210",
    msisdn="4915112345678",
    mccmnc="26201",
    operator="Telekom 3f9a1c07",
)


# ---------------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------------


def test_iccid_bcd_pads_19_digits_and_swaps():
    assert sim.iccid_bcd("8949012345678901234") == "989410325476981032F4"
    assert sim.iccid_bcd("89860318640220133897") == "98683081462002318379"
    with pytest.raises(ValueError, match="19 or 20"):
        sim.iccid_bcd("894901234567890123")


def test_msisdn_record_odd_and_even_numbers():
    assert sim.msisdn_record("4915112345678", international=True) == MSISDN_RECORD
    even = sim.msisdn_record("15551234", international=False)
    assert even == "FF" * 14 + "05" + "81" + "51552143" + "FF" * 6 + "FFFF"
    assert len(even) == 56
    assert sim.decode_msisdn_record(MSISDN_RECORD) == ("4915112345678", True)
    assert sim.decode_msisdn_record(even) == ("15551234", False)
    assert sim.decode_msisdn_record("FF" * 28) == ("", False)
    with pytest.raises(ValueError, match="1-20 digits"):
        sim.msisdn_record("+4915112345678", international=True)


def test_msisdn_digits_adds_the_calling_code_to_national_numbers():
    assert sim.msisdn_digits("+4915112345678", "49") == ("4915112345678", True)
    assert sim.msisdn_digits("015112345678", "49") == ("4915112345678", True)
    assert sim.msisdn_digits("15112345678", "") == ("15112345678", False)
    # 00 is the international prefix; only one trunk 0 is dropped.
    assert sim.msisdn_digits("004915112345678", "1") == ("4915112345678", True)
    assert sim.msisdn_digits("004915112345678", "") == ("4915112345678", True)
    assert sim.msisdn_digits("0301234567", "49") == ("49301234567", True)


def _parcel_words(text: str) -> str:
    data = (0).to_bytes(4, "little") + len(text).to_bytes(4, "little")
    data += text.encode("utf-16-le") + b"\0\0"
    data += b"\0" * (-len(data) % 4)
    words = [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]
    return " ".join(f"{w:08x}" for w in words)


def test_parcel_strings_are_decoded():
    out = f"Result: Parcel(\n  0x00000000: {_parcel_words('+4915112345678')} '...')"
    assert sim.decode_parcel_string(out) == "+4915112345678"
    # An exception (SecurityException) and a null string.
    assert sim.decode_parcel_string("Result: Parcel(ffffffb5 00000000 '....')") is None
    assert sim.decode_parcel_string("Result: Parcel(00000000 ffffffff '....')") is None
    assert sim.decode_parcel_string("service: not found") is None
    # The first word right after "Parcel(" counts (one-line replies).
    assert (
        sim.decode_parcel_string("Result: Parcel(00000000 00000001 00000041 '.')")
        == "A"
    )


# ---------------------------------------------------------------------------
# file patches
# ---------------------------------------------------------------------------


def test_iccprofile_patch_changes_only_the_sim_values():
    patched = sim.patch_iccprofile(TEMPLATE, VALUES)
    before, after = TEMPLATE.splitlines(), patched.splitlines()
    changed = [(a, b) for a, b in zip(before, after, strict=True) if a != b]
    assert len(changed) == 5
    assert "144,0,989410325476981032F4</SIMIO>" in patched
    assert "<CCID>8949012345678901234</CCID>" in patched
    assert "<CIMI>262019876543210</CIMI>" in patched
    assert f"144,0,{MSISDN_RECORD}</SIMIO>" in patched
    assert 'p3="4" data="">144,0,00000002</SIMIO>' in patched
    # EF_MBDN (voice mail) and EF_PL are untouched.
    assert "07915155674523F1" in patched
    assert "144,0,FFFFFFFF</SIMIO>" in patched
    assert sim.read_iccprofile(patched) == SimValues(
        iccid=VALUES.iccid,
        imsi=VALUES.imsi,
        msisdn=VALUES.msisdn,
        mccmnc=VALUES.mccmnc,
    )


def test_stock_profile_reads_back_and_partial_patches_keep_the_rest():
    stock = sim.read_iccprofile(TEMPLATE)
    assert stock.iccid == "89860318640220133897"
    assert stock.imsi == "310260000000000"
    assert stock.mccmnc == "310260"
    assert stock.phone == "+15551234567"
    only_iccid = sim.patch_iccprofile(TEMPLATE, SimValues(iccid="8949" + "0" * 16))
    assert sim.read_iccprofile(only_iccid).imsi == stock.imsi
    assert sim.patch_iccprofile(TEMPLATE, SimValues()) == TEMPLATE


def test_unknown_template_structure_is_refused():
    broken = TEMPLATE.replace("<CIMI>310260000000000</CIMI>", "")
    with pytest.raises(sim.SimPatchError, match="EF_IMSI"):
        sim.patch_iccprofile(broken, SimValues(imsi="262019876543210"))


def test_numeric_operator_entry_is_added_or_replaced():
    added = sim.patch_numeric_operator(NUMERIC, "26201", "Telekom 3f9a1c07")
    assert added == NUMERIC.replace(
        "TMOBILE</item>\n",
        "TMOBILE</item>\n"
        '        <item numeric="26201">Telekom 3f9a1c07=Telekom 3f9a1c07</item>\n',
    )
    replaced = sim.patch_numeric_operator(NUMERIC, "310260", "A&B <x>=y")
    assert '<item numeric="310260">A&amp;B &lt;x&gt; y=A&amp;B &lt;x&gt; y</item>' in (
        replaced
    )
    assert replaced.count("<item") == 1
    crlf = NUMERIC.replace("\n", "\r\n")
    assert "\r\n" + " " * 8 + '<item numeric="26201">' in sim.patch_numeric_operator(
        crlf, "26201", ""
    )
    with pytest.raises(sim.SimPatchError):
        sim.patch_numeric_operator("<resources/>", "26201", "x")


# ---------------------------------------------------------------------------
# profile -> SIM values
# ---------------------------------------------------------------------------


@pytest.fixture
def profile_env(tmp_path, monkeypatch):
    monkeypatch.setenv(ident.PROFILES_DIR_ENV, str(tmp_path / "profiles"))
    from sandroid.config import get_config

    cfg = get_config().identity
    monkeypatch.setattr(cfg, "mode", "off")
    monkeypatch.setattr(cfg, "profile", "")
    monkeypatch.setattr(sim, "cache_root", lambda: tmp_path / "cache")
    return cfg


def _profile() -> ident.Profile:
    profile = ident.generate_profile("de")
    profile.token = "3f9a1c07"  # noqa: S105 - a canary token
    profile.seed = "hex:" + "11" * 32
    return profile


def test_sim_values_of_a_generated_profile():
    profile = _profile()
    values = sim.sim_values(profile)
    rendered = {k: ident.render_value(profile, v) for k, v in profile.values.items()}
    assert values.iccid == rendered["iccid"]
    assert values.imsi == rendered["imsi"]
    assert values.mccmnc == "26201"
    assert values.phone == "+49" + rendered["phone_number"]
    assert values.operator == "Telekom 3f9a1c07"


def test_sim_values_need_native_enabled_values():
    profile = _profile()
    for kind in sim.SIM_KINDS:
        profile.values[kind].provider = "hook"
    assert sim.sim_values(profile) is None
    profile.values["sim_mccmnc"].provider = ""
    values = sim.sim_values(profile)
    # The SIM's MCC/MNC comes from its IMSI: zeros after the MCC/MNC.
    assert values.imsi == "262010000000000"
    assert not values.iccid
    profile.values["iccid"].value, profile.values["iccid"].template = "123", None
    assert sim.sim_values(profile) is None  # invalid profile


# ---------------------------------------------------------------------------
# private sysdir
# ---------------------------------------------------------------------------


@pytest.fixture
def image(tmp_path) -> Path:
    """A fake system image directory with a read-only data/ tree."""
    root = tmp_path / "sdk" / "system-images" / "android-35" / "gp" / "arm64-v8a"
    modem = root / "data" / "misc" / "modem_simulator"
    (modem / "etc" / "modem_simulator" / "files").mkdir(parents=True)
    (modem / "iccprofile_for_sim0.xml").write_text(TEMPLATE, encoding="utf-8")
    (modem / sim.NUMERIC_OPERATOR).write_text(NUMERIC, encoding="utf-8")
    (root / "data" / "local.prop").write_text("x=1\n", encoding="utf-8")
    (root / "system.img").write_bytes(b"system")
    (root / "kernel-ranchu").write_bytes(b"kernel")
    for dirpath, dirs, files in os.walk(root / "data", topdown=False):
        for name in files:
            (Path(dirpath) / name).chmod(0o444)
        for name in dirs:
            (Path(dirpath) / name).chmod(0o555)
    yield root
    for dirpath, dirs, _files in os.walk(root / "data"):
        for name in dirs:
            (Path(dirpath) / name).chmod(0o755)


def test_private_sysdir_links_the_image_and_patches_a_data_copy(image, tmp_path):
    target = tmp_path / "cache" / "identity-sysdir" / "Dev1"
    assert sim.build_private_sysdir(image, target, VALUES) == target
    assert (target / "system.img").is_symlink()
    assert (target / "system.img").readlink() == image / "system.img"
    assert (target / "kernel-ranchu").read_bytes() == b"kernel"
    data = target / "data"
    assert data.is_dir()
    assert not data.is_symlink()
    assert (data / "local.prop").read_text(encoding="utf-8") == "x=1\n"
    icc = data / sim.MODEM_DIR.relative_to("data") / "iccprofile_for_sim0.xml"
    assert "<CIMI>262019876543210</CIMI>" in icc.read_text(encoding="utf-8")
    numeric = data / sim.MODEM_DIR.relative_to("data") / sim.NUMERIC_OPERATOR
    assert '"26201">Telekom 3f9a1c07=' in numeric.read_text(encoding="utf-8")
    # The image itself is untouched.
    original = image / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    assert original.read_text(encoding="utf-8") == TEMPLATE


def test_rebuild_replaces_the_old_dir_and_clears_leftovers(image, tmp_path):
    base = tmp_path / "cache" / "identity-sysdir"
    target = base / "Dev1"
    sim.build_private_sysdir(image, target, VALUES)
    (base / ".Dev1.tmp-dead").mkdir()  # an interrupted build, long ago
    os.utime(base / ".Dev1.tmp-dead", (1, 1))
    (base / ".Dev1.old-dead").mkdir()
    (base / ".Dev1.old-ro" / "data").mkdir(parents=True)  # read-only copy
    (base / ".Dev1.old-ro" / "data").chmod(0o555)
    (base / ".Dev1.old-ro").chmod(0o555)
    (base / ".Dev10.tmp-live").mkdir()  # another AVD's build: kept
    other = SimValues(
        iccid="8949" + "1" * 15 + ident.luhn_check_digit("8949" + "1" * 15)
    )
    sim.build_private_sysdir(image, target, other)
    icc = target / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    assert sim.read_iccprofile(icc.read_text(encoding="utf-8")).iccid == other.iccid
    assert sorted(p.name for p in base.iterdir()) == [".Dev10.tmp-live", "Dev1"]
    # A young build directory may be another process's build: kept.
    (base / ".Dev1.tmp-busy").mkdir()
    sim.build_private_sysdir(image, target, VALUES)
    assert (base / ".Dev1.tmp-busy").is_dir()


def test_a_failed_patch_writes_nothing(image, tmp_path):
    target = tmp_path / "cache" / "identity-sysdir" / "Dev1"
    sim.build_private_sysdir(image, target, VALUES)
    with pytest.raises(ValueError, match="19 or 20"):
        sim.build_private_sysdir(image, target, SimValues(iccid="12"))
    icc = target / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    assert "<CCID>8949012345678901234</CCID>" in icc.read_text(encoding="utf-8")
    assert [p.name for p in target.parent.iterdir()] == ["Dev1"]


# ---------------------------------------------------------------------------
# launch hooks
# ---------------------------------------------------------------------------


@pytest.fixture
def avd(tmp_path, image, monkeypatch, profile_env):
    """AVD ``Dev1`` whose config.ini names the fake image (SDK-relative)."""
    avd_dir = tmp_path / "avd" / "Dev1.avd"
    avd_dir.mkdir(parents=True)
    rel = image.relative_to(tmp_path / "sdk")
    (avd_dir / "config.ini").write_text(f"image.sysdir.1={rel}/\n", encoding="utf-8")
    monkeypatch.setattr(emulator, "sdk_root", lambda: tmp_path / "sdk")
    monkeypatch.setattr(emulator, "_HOOKS", {"pre_launch": [], "post_stop": []})
    return avd_dir


def _context(avd_dir: Path, *extra: str) -> emulator.LaunchContext:
    return emulator.LaunchContext(
        avd="Dev1",
        avd_dir=avd_dir,
        port=5580,
        options=emulator.AvdLaunchOptions(extra_args=tuple(extra)),
    )


def _activate(profile_env) -> ident.Profile:
    profile = ident.get_identity_service().save(_profile())
    profile_env.mode, profile_env.profile = "profile", profile.id
    return profile


def test_pre_launch_is_a_no_op_when_identity_mode_is_off(avd, tmp_path):
    ident.get_identity_service().save(_profile())
    context = _context(avd)
    assert sim.pre_launch(context) == ()
    assert not (tmp_path / "cache").exists()
    assert context.record == {}  # nothing in the launch record


def test_pre_launch_builds_the_sysdir_and_post_stop_removes_it(avd, profile_env):
    profile = _activate(profile_env)
    context = _context(avd)
    args = sim.pre_launch(context)
    assert args == ("-sysdir", str(sim.sysdir_path("Dev1")))
    icc = Path(args[1]) / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    built = sim.read_iccprofile(icc.read_text(encoding="utf-8"))
    assert built.iccid == ident.render_value(profile, profile.values["iccid"])
    # The launch record says which profile's SIM the emulator starts with.
    noted = context.record[sim.RECORD_KEY]
    assert noted["profile"] == profile.id
    assert noted["sysdir"] == args[1]
    assert noted["values"]["iccid"] == built.iccid
    assert sim.SimValues(**noted["values"]) == sim.active_sim_values()
    json.dumps(context.record)  # JSON-ready
    # A second launch tolerates the leftover of the first.
    assert sim.pre_launch(_context(avd)) == args
    sim.post_stop(_context(avd))
    assert not Path(args[1]).exists()
    sim.post_stop(_context(avd))  # idempotent
    assert sim.sysdir_path("Dev1").parent.is_dir()


def test_pre_launch_leaves_a_launch_with_its_own_sysdir_alone(avd, profile_env):
    profile = _activate(profile_env)
    context = _context(avd, "-sysdir", "/elsewhere")
    assert sim.pre_launch(context) == ()
    assert not sim.sysdir_path("Dev1").exists()
    assert context.record[sim.RECORD_KEY] == {
        "profile": profile.id,
        "skipped": sim.OWN_SYSDIR,
    }


def test_pre_launch_without_native_sim_values_or_image(avd, profile_env, image):
    profile = _activate(profile_env)
    for kind in sim.SIM_KINDS:
        profile.values[kind].enabled = False
    ident.get_identity_service().save(profile)
    assert sim.pre_launch(_context(avd)) == ()
    for kind in sim.SIM_KINDS:
        profile.values[kind].enabled = True
    ident.get_identity_service().save(profile)
    (avd / "config.ini").write_text("image.sysdir.1=nowhere/\n", encoding="utf-8")
    context = _context(avd)
    assert sim.pre_launch(context) == ()
    assert context.record[sim.RECORD_KEY]["skipped"] == sim.NO_IMAGE


def test_launch_runs_the_hooks_and_appends_the_sysdir(avd, profile_env, monkeypatch):
    _activate(profile_env)
    sim.install_launch_hooks()
    sim.install_launch_hooks()  # idempotent
    hooks = emulator._HOOKS
    assert hooks == {"pre_launch": [sim.pre_launch], "post_stop": [sim.post_stop]}
    monkeypatch.setattr(emulator, "avd_dir", lambda name: avd)
    context = emulator._launch_context("Dev1", 5580, emulator.AvdLaunchOptions())
    args = emulator._run_pre_launch_hooks(context)
    assert args[0] == "-sysdir"
    emulator._run_post_stop_hooks(context)
    assert not Path(args[1]).exists()
    sim.uninstall_launch_hooks()
    assert emulator._HOOKS == {"pre_launch": [], "post_stop": []}


def test_running_sim_reads_what_the_emulator_copied(avd, monkeypatch):
    modem = avd / "modem_simulator"
    modem.mkdir()
    (modem / "iccprofile_for_sim0.xml").write_text(
        sim.patch_iccprofile(TEMPLATE, VALUES), encoding="utf-8"
    )
    monkeypatch.setattr(
        emulator, "avd_dir", lambda name: avd if name == "Dev1" else None
    )
    found = sim.running_sim("emulator-5580", "Dev1")
    assert found.iccid == VALUES.iccid
    assert found.value_of("phone_number") == "+4915112345678"
    assert found.value_of("sim_mccmnc") == "26201"
    assert sim.running_sim("emulator-5580", "Other") is None
    assert sim.running_sim("R58M123", "Dev1") is None
    assert sim.launched_sim(avd / "missing") is None


def test_the_copy_never_writes_through_a_link_into_the_sdk(image, tmp_path):
    modem = image / sim.MODEM_DIR
    modem.chmod(0o755)
    real = tmp_path / "sdk-shared.xml"
    real.write_text(TEMPLATE, encoding="utf-8")
    (modem / "iccprofile_for_sim0.xml").chmod(0o644)
    (modem / "iccprofile_for_sim0.xml").unlink()
    (modem / "iccprofile_for_sim0.xml").symlink_to(real)
    target = tmp_path / "cache" / "identity-sysdir" / "Dev1"
    sim.build_private_sysdir(image, target, VALUES)
    copy = target / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    assert not copy.is_symlink()
    assert "<CIMI>262019876543210</CIMI>" in copy.read_text(encoding="utf-8")
    assert real.read_text(encoding="utf-8") == TEMPLATE
    # The copy of a read-only data/ is owner-writable and removable.
    assert (target / "data").stat().st_mode & 0o777 == 0o700
    sim._rmtree(target)
    assert not target.exists()


def test_a_host_without_symlinks_launches_without_the_sim(
    avd, profile_env, monkeypatch
):
    _activate(profile_env)

    def no_links(src, dst, *a, **k):
        raise OSError(1, "A required privilege is not held by the client")

    monkeypatch.setattr(sim.os, "symlink", no_links)
    assert sim.pre_launch(_context(avd)) == ()
    assert [p.name for p in sim.sysdir_path("Dev1").parent.iterdir()] == []


def test_a_running_instance_keeps_its_sysdir(avd, profile_env, monkeypatch):
    _activate(profile_env)
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [Path("x.lock")])
    assert sim.pre_launch(_context(avd)) == ()  # nothing to reuse: no rebuild
    assert not sim.sysdir_path("Dev1").exists()
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [])
    args = sim.pre_launch(_context(avd))
    stamp = (Path(args[1]) / "data").stat().st_ino
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [Path("x.lock")])
    assert sim.pre_launch(_context(avd)) == args  # the matching one, reused
    assert (Path(args[1]) / "data").stat().st_ino == stamp


def test_the_sysdir_argument_is_absolute(avd, profile_env, monkeypatch, tmp_path):
    _activate(profile_env)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sim, "cache_root", lambda: Path("relative-cache"))
    args = sim.pre_launch(_context(avd))
    assert Path(args[1]).is_absolute()
    assert Path(args[1]) == tmp_path / "relative-cache" / "identity-sysdir" / "Dev1"


def test_restart_blocker_names_the_real_reason(avd, profile_env, image):
    profile = _activate(profile_env)
    running = sim.RunningEmulator("emulator-5580", "Dev1", avd)
    assert sim.restart_blocker(running, profile) == ""
    assert sim.restart_blocker(None, profile) == sim.NOT_STARTABLE
    unknown = sim.RunningEmulator("emulator-5580", "Gone")
    assert sim.restart_blocker(unknown, profile) == sim.AVD_UNKNOWN
    own = sim.RunningEmulator("emulator-5580", "Dev1", avd, own_sysdir=True)
    assert sim.restart_blocker(own, profile) == sim.OWN_SYSDIR
    icc = image / sim.MODEM_DIR / "iccprofile_for_sim0.xml"
    icc.parent.chmod(0o755)
    icc.chmod(0o644)
    icc.write_text(TEMPLATE.replace("<CIMI>310260000000000</CIMI>", ""), "utf-8")
    assert sim.restart_blocker(running, profile) == sim.UNKNOWN_TEMPLATE
    icc.unlink()
    assert sim.restart_blocker(running, profile) == sim.NO_TEMPLATE
    profile_env.profile = "other"
    assert sim.restart_blocker(running, profile) == sim.NOT_ACTIVE
    profile_env.mode = "off"
    assert sim.restart_blocker(running, profile) == sim.MODE_OFF


def test_running_emulator_has_a_launch_token(avd, monkeypatch):
    monkeypatch.setattr(emulator, "avd_dir", lambda name: avd)
    (avd / "hardware-qemu.ini").write_text("x\n", encoding="utf-8")
    os.utime(avd / "hardware-qemu.ini", ns=(1, 111))
    monkeypatch.setattr(emulator, "launch_record", lambda serial: None)
    found = sim.running_emulator("emulator-5580", "Dev1")
    assert found.token == "ini:111"  # noqa: S105 - a launch id, not a secret
    assert found.sim is None
    assert not found.own_sysdir
    assert sim.running_emulator("R58M123", "Dev1") is None


def test_running_emulator_uses_sandroids_launch_record(avd, monkeypatch):
    monkeypatch.setattr(
        emulator, "avd_dir", lambda name: avd if name == "Dev1" else None
    )
    monkeypatch.setattr(
        emulator, "avd_name_of", lambda serial: pytest.fail("console asked")
    )
    (avd / "hardware-qemu.ini").write_text("x\n", encoding="utf-8")
    record = {
        "launch_id": "L1",
        "avd": "Dev1",
        "options": {"extra_args": ["-no-snapshot-save"]},
    }
    monkeypatch.setattr(emulator, "launch_record", lambda serial: record)
    found = sim.running_emulator("emulator-5580")
    assert found.avd == "Dev1"  # from the record, not the console
    assert found.token == "launch:L1"  # noqa: S105 - a launch id, not a secret
    assert not found.own_sysdir
    # The token follows the launch, not the ini file's time.
    os.utime(avd / "hardware-qemu.ini", ns=(1, 222))
    assert sim.running_emulator("emulator-5580").token == "launch:L1"  # noqa: S105
    record = {**record, "launch_id": "L2"}
    assert sim.running_emulator("emulator-5580").token == "launch:L2"  # noqa: S105
    record["options"] = {"extra_args": ["-sysdir=/mine"]}
    assert sim.running_emulator("emulator-5580").own_sysdir


def test_post_stop_keeps_the_sysdir_of_a_running_instance(
    avd, profile_env, monkeypatch
):
    _activate(profile_env)
    args = sim.pre_launch(_context(avd))
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [Path("x.lock")])
    sim.post_stop(_context(avd))  # a refused duplicate launch
    assert Path(args[1]).is_dir()
    monkeypatch.setattr(emulator, "avd_lock_files", lambda name: [])
    sim.post_stop(_context(avd))
    assert not Path(args[1]).exists()


def test_dangling_links_are_skipped_and_copy_errors_degrade(
    avd, profile_env, image, monkeypatch
):
    _activate(profile_env)
    data = image / "data"
    data.chmod(0o755)
    (data / "gone").symlink_to(image / "nowhere")
    args = sim.pre_launch(_context(avd))
    assert args[0] == "-sysdir"
    assert not (Path(args[1]) / "data" / "gone").exists()

    def broken_copy(src, dst, *a, **k):
        raise shutil.Error([(str(src), str(dst), "unreadable")])

    monkeypatch.setattr(sim.shutil, "copyfile", broken_copy)
    sim.post_stop(_context(avd))
    assert sim.pre_launch(_context(avd)) == ()
    assert [p.name for p in sim.sysdir_path("Dev1").parent.iterdir()] == []


def test_restart_blocker_names_an_unknown_mcc_mnc(avd, profile_env):
    profile = _activate(profile_env)
    del profile.values["sim_mccmnc"]
    profile.preset = ""
    running = sim.RunningEmulator("emulator-5580", "Dev1", avd)
    assert sim.restart_blocker(running, profile) == sim.MNC_UNKNOWN
