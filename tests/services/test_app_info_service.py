"""Tests for :mod:`sandroid.services.app_info_service` (no device needed).

Device output is replayed from recorded-format fixture strings: ``Adb``'s
classmethods are replaced on ``sandroid.core.adb.Adb`` with ``staticmethod``
fakes (same convention as ``tests/ai/tools/test_app_query.py``).
"""

import json
import os
import re
import shlex
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sandroid.analysis import static_analysis
from sandroid.core.adb import Adb
from sandroid.services import app_info_service as ais

PKG = "com.example.app"

# ---------------------------------------------------------------------------
# Fixtures: recorded output formats
# ---------------------------------------------------------------------------

#: API 30 (Android 11) ``dumpsys package`` excerpt.
DUMPSYS_PACKAGE_API30 = """\
Permissions:
  Permission [com.example.app.permission.C2D_MESSAGE] (5d1a2b3):
    sourcePackage=com.example.app
    uid=10123 gids=null type=0 prot=signature
    perm=Permission{1f2e3d com.example.app.permission.C2D_MESSAGE}
    packageSetting=PackageSetting{9a8b7c com.example.app/10123}

Packages:
  Package [com.example.app] (b2c3d4e):
    userId=10123
    pkg=Package{a1b2c3 com.example.app}
    versionCode=42 minSdk=24 targetSdk=30
    versionName=1.2.3
    requested permissions:
      android.permission.INTERNET
      android.permission.CAMERA
      android.permission.ACCESS_FINE_LOCATION
      android.permission.READ_EXTERNAL_STORAGE: restricted=true
      com.example.app.permission.C2D_MESSAGE
    install permissions:
      android.permission.INTERNET: granted=true
      com.example.app.permission.C2D_MESSAGE: granted=true
    User 0: ceDataInode=4321 installed=true hidden=false suspended=false stopped=false notLaunched=false enabled=0 instant=false virtual=false
      gids=[3003]
      runtime permissions:
        android.permission.CAMERA: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET|USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED]
        android.permission.READ_EXTERNAL_STORAGE: granted=true, flags=[ RESTRICTION_INSTALLER_EXEMPT]
    User 10: ceDataInode=0 installed=true hidden=false
      runtime permissions:
        android.permission.CAMERA: granted=true, flags=[ USER_SET]

Queries:
  system apps queryable: false
"""

#: API 34/35 (Android 14/15) ``dumpsys package`` excerpt with a declared
#: permissions section and a hidden-system-package copy.
DUMPSYS_PACKAGE_API34 = """\
Packages:
  Package [com.example.app] (7f6e5d4):
    appId=10150
    versionCode=7 minSdk=26 targetSdk=34
    declared permissions:
      com.example.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: prot=signature, INSTALLED
    requested permissions:
      android.permission.POST_NOTIFICATIONS
      android.permission.FOREGROUND_SERVICE
      android.permission.FOREGROUND_SERVICE_LOCATION
      com.example.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
    install permissions:
      android.permission.FOREGROUND_SERVICE: granted=true
      android.permission.FOREGROUND_SERVICE_LOCATION: granted=true
      com.example.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION: granted=true
    User 0: ceDataInode=99 installed=true hidden=false suspended=false distractionFlags=0 stopped=false notLaunched=false enabled=0 instant=false virtual=false quarantined=false
      runtime permissions:
        android.permission.POST_NOTIFICATIONS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED|REVOKE_WHEN_REQUESTED]

Hidden system packages:
  Package [com.example.app] (1a1a1a1):
    requested permissions:
      android.permission.SHOULD_NOT_APPEAR
"""

PM_DANGEROUS = """\
All Permissions:

group:android.permission-group.CAMERA
  permission:android.permission.CAMERA

group:android.permission-group.LOCATION
  permission:android.permission.ACCESS_FINE_LOCATION
  permission:android.permission.ACCESS_COARSE_LOCATION

ungrouped:
  permission:android.permission.POST_NOTIFICATIONS
"""

#: ``cmd appops get`` on API 30 (semicolon format, Uid-mode prefix).
APPOPS_API30 = """\
Uid mode: COARSE_LOCATION: foreground
LEGACY_STORAGE: allow
COARSE_LOCATION: allow; time=+3m10s510ms ago
CAMERA: ignore; rejectTime=+1h2m ago
READ_CLIPBOARD: allow; time=+5m3s ago
READ_EXTERNAL_STORAGE: allow; time=+1d2h3m4s ago; duration=+12ms
"""

#: ``cmd appops get`` on API 33/34 (running op, time + rejectTime).
APPOPS_API34 = """\
Uid mode: SCHEDULE_EXACT_ALARM: allow
CAMERA: allow; time=+2s ago (running)
RECORD_AUDIO: foreground; time=+10m ago; rejectTime=+9m ago; duration=+4s200ms
TOAST_WINDOW: allow; time=+1h ago; duration=+3s
POST_NOTIFICATION: deny; rejectTime=+30s ago
"""

#: Block format (``dumpsys appops --package`` and newer ``cmd appops get``)
#: with attribution-tag groups and process-state markers (API 35/36).
APPOPS_API36_BLOCK = """\
Current AppOps Service state:
  Uid 10150:
    state=top
    capability=LCMNFOB
      COARSE_LOCATION: mode=foreground
    Package com.example.app:
      READ_CLIPBOARD (allow):
        null=[
          Access: [top-s] 2026-05-01 12:00:00.123 (-5m3s123ms)
        ]
        tagX=[
          Access: [bg-s] 2026-05-01 11:00:00.000 (-1h5m3s)
        ]
      CAMERA (ignore / switch COARSE_LOCATION=allow):
        null=[
          Reject: [bg-s]2026-05-01 11:50:00.000 (-15m)
        ]
      FINE_LOCATION (foreground):
        null=[
          Access: [fg-s] 2026-05-01 12:04:00.000 (-1m3s) duration=+2s500ms
        ]
"""

#: ``dumpsys activity services <pkg>`` on API 34 (``types=`` bitmask).
SERVICES_API34 = """\
ACTIVITY MANAGER SERVICES (dumpsys activity services)
  User 0 active services:
  * ServiceRecord{3b9e5d1 u0 com.example.app/.LocationService c:com.example.app}
    intent={cmp=com.example.app/.LocationService}
    packageName=com.example.app
    processName=com.example.app
    app=ProcessRecord{c1d2e3f 4321:com.example.app/u0a150}
    isForeground=true foregroundId=1001 types=0x00000048 foregroundNoti=Notification(channel=loc pri=0)
    createTime=-5m2s ago startingBgTimeout=--
  * ServiceRecord{5a5a5a5 u0 com.example.app/.SyncService}
    intent={cmp=com.example.app/.SyncService}
    app=ProcessRecord{c1d2e3f 4321:com.example.app/u0a150}
    createTime=-1m ago startingBgTimeout=--
  * ServiceRecord{6b6b6b6 u0 com.other.app/.Svc}
    isForeground=true foregroundId=7 types=0x00000001 foregroundNoti=Notification()
"""

#: Older ``foregroundServiceType=`` spelling (API 30/31).
SERVICES_API30 = """\
  * ServiceRecord{abc1234 u0 com.example.app/.PlayerService}
    app=ProcessRecord{def5678 999:com.example.app:player/u0a150}
    isForeground=true foregroundId=5 foregroundNoti=Notification(channel=media)
    foregroundServiceType=0x00000002
"""

FOOTPRINT_ROOT = f"""\
51234\t/data/data/{PKG}
@@SANDROID_SEP@@
2048\t/sdcard/Android/data/{PKG}
@@SANDROID_SEP@@
{PKG}_preferences.xml
settings.xml
com.google.android.gms.measurement.prefs.xml
@@SANDROID_SEP@@
app.db
app.db-journal
app.db-wal
cache.db
"""

FOOTPRINT_NOROOT = f"""\
du: /data/data/{PKG}: Permission denied
@@SANDROID_SEP@@
du: /sdcard/Android/data/{PKG}: No such file or directory
@@SANDROID_SEP@@
ls: /data/data/{PKG}/shared_prefs: Permission denied
@@SANDROID_SEP@@
ls: /data/data/{PKG}/databases: Permission denied
"""


class FakeAdb:
    """Records adb commands; answers by the first matching substring."""

    def __init__(self, answers: dict[str, str]):
        self.answers = answers
        self.calls: list[tuple[str, str | None]] = []

    def __call__(self, command, serial=None, timeout=30):
        self.calls.append((command, serial))
        for needle, answer in self.answers.items():
            if needle in command:
                return answer, ""
        return "", ""


@pytest.fixture
def fake_adb(monkeypatch):
    def install(answers):
        fake = FakeAdb(answers)
        monkeypatch.setattr(Adb, "send_adb_command", staticmethod(fake))
        return fake

    return install


@pytest.fixture
def cache_root(monkeypatch, tmp_path):
    root = tmp_path / "apk_cache"
    monkeypatch.setattr(ais, "default_apk_cache_root", lambda: root)
    return root


# ---------------------------------------------------------------------------
# Layering
# ---------------------------------------------------------------------------


def test_service_never_imports_ai():
    source = Path(ais.__file__).read_text()
    assert not re.search(r"^\s*(from|import) sandroid\.ai\b", source, re.M)


def test_parse_pm_path_output_is_shared_with_ai_tools():
    from sandroid.ai.tools import _shared

    assert _shared.parse_pm_path_output is ais.parse_pm_path_output


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def test_permission_state_api30():
    state = ais.parse_permission_state(
        DUMPSYS_PACKAGE_API30,
        PKG,
        dangerous=ais.parse_dangerous_permissions(PM_DANGEROUS),
    )
    by_name = {p.name: p for p in state.permissions}

    assert state.ok
    internet = by_name["android.permission.INTERNET"]
    assert (internet.kind, internet.granted, internet.requested) == (
        "install",
        True,
        True,
    )
    camera = by_name["android.permission.CAMERA"]
    # User 0 wins over the work-profile user 10.
    assert (camera.kind, camera.granted) == ("runtime", False)
    assert camera.flags == ["USER_SENSITIVE_WHEN_GRANTED", "USER_SENSITIVE_WHEN_DENIED"]
    assert (camera.protection, camera.protection_source) == ("dangerous", "pm")
    fine = by_name["android.permission.ACCESS_FINE_LOCATION"]
    assert fine.granted is True
    assert "USER_SET" in fine.flags
    storage = by_name["android.permission.READ_EXTERNAL_STORAGE"]
    assert storage.restricted is True
    assert storage.protection_source == "runtime-section"
    c2d = by_name["com.example.app.permission.C2D_MESSAGE"]
    assert (c2d.protection, c2d.protection_source) == ("signature", "dumpsys")
    assert state.declared == {"com.example.app.permission.C2D_MESSAGE": "signature"}


def test_permission_state_api34_declared_and_hidden_copy_ignored():
    state = ais.parse_permission_state(
        DUMPSYS_PACKAGE_API34,
        PKG,
        manifest_protection={"android.permission.FOREGROUND_SERVICE": "normal|instant"},
    )
    by_name = {p.name: p for p in state.permissions}

    assert "android.permission.SHOULD_NOT_APPEAR" not in by_name
    assert by_name["android.permission.POST_NOTIFICATIONS"].granted is False
    assert by_name["android.permission.FOREGROUND_SERVICE"].protection == "normal"
    assert (
        by_name["android.permission.FOREGROUND_SERVICE"].protection_source == "manifest"
    )
    assert by_name["android.permission.FOREGROUND_SERVICE_LOCATION"].protection is None
    declared = by_name["com.example.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"]
    assert declared.protection == "signature"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "empty dumpsys output"),
        ("Unable to find package: com.example.app", "package not found"),
    ],
)
def test_permission_state_unknown_package(text, reason):
    state = ais.parse_permission_state(text, PKG)
    assert not state.ok
    assert reason in state.reason


def test_get_permission_state_uses_serial_and_never_raises(fake_adb, monkeypatch):
    fake = fake_adb(
        {"dumpsys package": DUMPSYS_PACKAGE_API30, "list permissions": PM_DANGEROUS}
    )
    state = ais.get_permission_state(PKG, serial="emulator-5556")
    assert state.ok
    assert all(serial == "emulator-5556" for _cmd, serial in fake.calls)

    def boom(*_a, **_k):
        raise RuntimeError("adb died")

    monkeypatch.setattr(ais, "parse_permission_state", boom)
    broken = ais.get_permission_state(PKG)
    assert not broken.ok
    assert "adb died" in broken.reason
    assert not ais.get_permission_state("bad;pkg").ok


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("dangerous|instant", "dangerous"),
        ("0x00000002", "signature"),
        ("0x00000012", "signature"),
        (1, "dangerous"),
        ("None", None),
        (None, None),
    ],
)
def test_normalize_protection(value, expected):
    assert ais.normalize_protection(value) == expected


# ---------------------------------------------------------------------------
# AppOps
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("+5m3s ago", 303.0),
        ("+1d2h3m4s", 93784.0),
        ("-5m3s123ms", 303.123),
        ("+12ms", 0.012),
        ("0", 0.0),
        ("--", None),
        (None, None),
    ],
)
def test_parse_android_duration(text, seconds):
    assert ais.parse_android_duration(text) == seconds


def test_appops_api30_semicolon_format():
    ops = {(o.scope, o.op): o for o in ais.parse_appops(APPOPS_API30)}

    assert ops[("uid", "COARSE_LOCATION")].mode == "foreground"
    coarse = ops[("package", "COARSE_LOCATION")]
    assert coarse.mode == "allow"
    assert coarse.last_access == "+3m10s510ms ago"
    assert coarse.last_access_ago_s == 190.51
    assert coarse.permission == "android.permission.ACCESS_COARSE_LOCATION"
    camera = ops[("package", "CAMERA")]
    assert camera.mode == "ignore"
    assert camera.last_reject_ago_s == 3720.0
    assert camera.last_access is None
    clip = ops[("package", "READ_CLIPBOARD")]
    assert clip.permission is None
    assert clip.last_access_ago_s == 303.0
    storage = ops[("package", "READ_EXTERNAL_STORAGE")]
    assert storage.duration_s == 0.012
    # No state markers in this format.
    assert clip.foreground is None
    assert clip.background is None


def test_appops_api34_running_and_reject():
    ops = {o.op: o for o in ais.parse_appops(APPOPS_API34) if o.scope == "package"}

    assert ops["CAMERA"].running is True
    assert ops["CAMERA"].last_access_ago_s == 2.0
    audio = ops["RECORD_AUDIO"]
    assert (audio.mode, audio.last_reject_ago_s, audio.duration_s) == (
        "foreground",
        540.0,
        4.2,
    )
    assert ops["TOAST_WINDOW"].permission is None
    assert ops["POST_NOTIFICATION"].mode == "deny"
    assert ops["POST_NOTIFICATION"].permission == (
        "android.permission.POST_NOTIFICATIONS"
    )


def test_appops_api36_block_format():
    ops = {(o.scope, o.op): o for o in ais.parse_appops(APPOPS_API36_BLOCK)}

    assert ops[("uid", "COARSE_LOCATION")].mode == "foreground"
    clip = ops[("package", "READ_CLIPBOARD")]
    assert clip.mode == "allow"
    assert clip.last_access == "2026-05-01 12:00:00.123"  # most recent tag
    assert clip.last_access_ago_s == 303.123
    assert clip.access_states == ["top-s", "bg-s"]
    assert clip.foreground is True
    assert clip.background is True
    camera = ops[("package", "CAMERA")]
    assert camera.mode == "ignore"
    assert camera.reject_states == ["bg-s"]
    assert camera.last_reject_ago_s == 900.0
    fine = ops[("package", "FINE_LOCATION")]
    assert fine.duration_s == 2.5
    assert fine.foreground is True
    assert fine.background is False


def test_get_appops_falls_back_to_dumpsys(fake_adb):
    fake = fake_adb({"cmd appops": "", "dumpsys appops": APPOPS_API36_BLOCK})
    state = ais.get_appops(PKG, serial="emulator-5554")

    assert state.ok
    assert state.source == "dumpsys appops"
    assert [c for c, _s in fake.calls] == [
        f"shell cmd appops get {PKG}",
        f"shell dumpsys appops --package {PKG}",
    ]
    assert {s for _c, s in fake.calls} == {"emulator-5554"}


def test_get_appops_reports_reason_on_errors(fake_adb):
    fake_adb({"appops": "Error: Unknown package: com.example.app"})
    state = ais.get_appops(PKG)
    assert not state.ok
    assert "Unknown package" in state.reason

    fake_adb({})
    assert "device offline" in ais.get_appops(PKG).reason
    assert not ais.get_appops("not a package").ok


# ---------------------------------------------------------------------------
# Data footprint
# ---------------------------------------------------------------------------


def test_footprint_with_adb_root(fake_adb):
    fake = fake_adb({"du -sk": FOOTPRINT_ROOT, "shell id": "uid=0(root) gid=0(root)"})
    result = ais.get_data_footprint(PKG, serial="emulator-5554")

    assert result.root_method == "adb root"
    assert (result.private_kb, result.external_kb) == (51234, 2048)
    assert (result.shared_prefs_count, result.databases_count) == (3, 2)
    assert result.private_reason is None
    assert result.reason is None
    script_call = fake.calls[-1][0]
    # Whole script is one host-quoted word, device paths quoted inside it.
    assert script_call.startswith("shell '")
    assert "su " not in script_call


def test_footprint_without_root(fake_adb):
    fake = fake_adb({"du -sk": FOOTPRINT_NOROOT, "id": "uid=2000(shell)"})
    result = ais.get_data_footprint(PKG)

    assert result.root_method is None
    assert result.private_kb is None
    assert result.private_reason == "root required (enable adb root)"
    assert (result.external_kb, result.external_reason) == (None, "absent")
    assert result.shared_prefs_count is None
    assert result.databases_count is None
    # Probed plain shell, su -c and su 0 before giving up.
    probes = [c for c, _s in fake.calls if "du -sk" not in c]
    assert len(probes) == 3


def test_footprint_wraps_script_for_su(fake_adb):
    fake = fake_adb({"su -c": "uid=0(root)", "du -sk": FOOTPRINT_ROOT})
    result = ais.get_data_footprint(PKG)

    assert result.root_method == "su -c"
    assert "su -c " in fake.calls[-1][0]
    assert "du -sk" in fake.calls[-1][0]


def test_footprint_script_quotes_paths():
    script = ais.footprint_script(PKG)
    assert f"du -sk /data/data/{PKG}" in script  # plain names need no quotes
    assert ais.get_data_footprint("x;rm -rf /").reason.startswith("invalid")


def test_footprint_partial_du():
    out = FOOTPRINT_ROOT.replace(
        "51234\t", "du: /data/data/x/cache: Permission denied\n51234\t"
    )
    result = ais.parse_footprint_output(out, PKG, "su 0")
    assert result.private_kb == 51234
    assert result.private_reason.startswith("partial")
    assert ais.parse_footprint_output("", PKG).reason == "no output"


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def test_services_api34_types_bitmask():
    services = ais.parse_services(SERVICES_API34, PKG)

    assert [s.component for s in services] == [
        "com.example.app/.LocationService",
        "com.example.app/.SyncService",
    ]
    location = services[0]
    assert location.foreground
    assert location.foreground_id == 1001
    assert location.types == ["location", "camera"]
    assert (location.pid, location.process) == (4321, "com.example.app")
    assert location.created == "-5m2s"
    assert services[1].foreground is False
    assert services[1].types == []


def test_services_api30_foreground_service_type():
    (player,) = ais.parse_services(SERVICES_API30, PKG)
    assert player.types == ["mediaPlayback"]
    assert player.process == "com.example.app:player"


def test_get_running_services_state(fake_adb):
    fake_adb({"dumpsys activity services": SERVICES_API34})
    state = ais.get_running_services(PKG)
    assert state.ok
    assert len(state.foreground) == 1
    assert "services" in state.to_dict()

    fake_adb({})
    assert not ais.get_running_services(PKG).ok


@pytest.mark.parametrize(
    ("raw", "types"),
    [
        ("0x00000008", ["location"]),
        ("0xffffffff", ["manifest"]),
        ("0x40000000", ["specialUse"]),
        ("0", []),
        ("location|camera", ["location", "camera"]),
        (None, []),
    ],
)
def test_decode_fgs_types(raw, types):
    assert ais.decode_fgs_types(raw) == types


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

H1, H2, H3 = ("a" * 64, "b" * 64, "c" * 64)


def test_compute_apk_key():
    assert ais.compute_apk_key([H1.upper()]) == H1
    split_key = ais.compute_apk_key([H2, H1, H3])
    assert split_key == ais.compute_apk_key([H3, H2, H1])
    assert split_key not in (H1, H2, H3)
    assert len(split_key) == 64
    with pytest.raises(ValueError):
        ais.compute_apk_key([])


def test_cache_layout_and_meta_merge(cache_root):
    cache = ais.ApkCache()
    assert cache.root == cache_root
    assert cache.insight_dir == cache_root / "insight"

    overview = {"schema": ais.OVERVIEW_SCHEMA, "package": PKG}
    assert cache.write_entry(H1, overview=overview, meta_updates={"package": PKG})
    first = cache.read_meta(H1)
    assert cache.write_entry(H1, meta_updates={"version_code": 7})
    meta = cache.read_meta(H1)

    assert meta["created_at"] == first["created_at"]
    assert meta["updated_at"] >= first["updated_at"]
    assert meta["package"] == PKG
    assert meta["version_code"] == 7
    assert cache.read_overview(H1) == overview
    entry = cache_root / "apk" / H1
    assert sorted(p.name for p in entry.iterdir()) == ["meta.json", "overview.json"]
    assert [k for k, _m in cache.find(PKG)] == [H1]
    assert cache.find(PKG, version_code=8) == []


def test_cache_overview_schema_mismatch_is_a_miss(cache_root):
    cache = ais.ApkCache()
    cache.write_entry(H1, overview={"schema": -1})
    assert cache.read_overview(H1) is None


def test_disabled_cache_never_writes(cache_root):
    cache = ais.ApkCache(enabled=False)
    assert not cache.write_entry(H1, overview={"schema": 1})
    assert not cache_root.exists()
    assert cache.read_meta(H1) is None
    assert cache.find(PKG) == []


def test_cache_rejects_bad_keys(cache_root):
    with pytest.raises(ValueError):
        ais.ApkCache().entry_dir("../../etc")


def test_cache_lock_timeout_and_stale_lock(cache_root):
    cache = ais.ApkCache(lock_timeout=0.2, stale_lock_after=60)
    entry = cache_root / "apk" / H1
    entry.mkdir(parents=True)
    lock = entry / ".lock"
    lock.write_text("other writer")

    assert cache.write_entry(H1, meta_updates={"x": 1}) is False  # busy lock
    old = time.time() - 120
    os.utime(lock, (old, old))
    assert cache.write_entry(H1, meta_updates={"x": 1}) is True  # stale: broken
    assert not lock.exists()


def test_atomic_write_leaves_no_temp_files(cache_root):
    cache = ais.ApkCache()
    for i in range(3):
        cache.write_entry(H1, meta_updates={"i": i})
    names = os.listdir(cache_root / "apk" / H1)
    assert names == ["meta.json"]


# ---------------------------------------------------------------------------
# Static overview pipeline
# ---------------------------------------------------------------------------

PM_PATH = (
    "package:/data/app/~~x==/com.example.app-y==/base.apk\n"
    "package:/data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk\n"
)
SHA_OUT = (
    f"{H1}  /data/app/~~x==/com.example.app-y==/base.apk\n"
    f"{H2}  /data/app/~~x==/com.example.app-y==/split_config.arm64_v8a.apk\n"
)


def test_static_overview_cache_hit_needs_no_pull(fake_adb, cache_root, monkeypatch):
    fake = fake_adb({"pm path": PM_PATH, "sha256sum": SHA_OUT})
    key = ais.compute_apk_key([H1, H2])
    ais.ApkCache().write_entry(
        key, overview={"schema": ais.OVERVIEW_SCHEMA, "native_libs": []}
    )
    monkeypatch.setattr(
        ais, "_pull_apks", lambda *a, **k: pytest.fail("must not pull on a hit")
    )

    result = ais.get_static_overview(PKG, serial="emulator-5554")

    assert result.ok
    assert result.from_cache
    assert result.key == key
    sha_cmd = next(c for c, _s in fake.calls if "sha256sum" in c)
    device_cmd = shlex.split(sha_cmd)[1]  # host-quoted once, device-quoted inside
    assert "'/data/app/~~x==/com.example.app-y==/base.apk'" in device_cmd
    assert {s for _c, s in fake.calls} == {"emulator-5554"}


def test_static_overview_lookup_only_miss(fake_adb, cache_root):
    fake_adb({"pm path": PM_PATH, "sha256sum": SHA_OUT})
    result = ais.get_static_overview(PKG, allow_pull=False)
    assert not result.ok
    assert result.reason == "not cached yet"


def _fake_pull(tmp_path):
    def pull(package, dest_dir, serial=None):
        pulled = []
        for name, data in (("base.apk", b"base"), ("split.apk", b"split")):
            local = os.path.join(dest_dir, name)
            Path(local).write_bytes(data)
            pulled.append((f"/data/app/x/{name}", local))
        return pulled

    return pull


def test_static_overview_pull_builds_and_caches(
    fake_adb, cache_root, monkeypatch, tmp_path
):
    fake_adb({"pm path": "", "sha256sum": ""})  # hashing on device fails
    monkeypatch.setattr(ais, "androguard_available", lambda: True)
    monkeypatch.setattr(ais, "_pull_apks", _fake_pull(tmp_path))
    monkeypatch.setattr(
        ais,
        "build_apk_overview",
        lambda paths: {
            "schema": ais.OVERVIEW_SCHEMA,
            "package": PKG,
            "version_name": "1.0",
            "version_code": 3,
        },
    )

    result = ais.get_static_overview(PKG)

    expected_key = ais.compute_apk_key(
        [
            ais.hashlib.sha256(b"base").hexdigest(),
            ais.hashlib.sha256(b"split").hexdigest(),
        ]
    )
    assert result.ok
    assert not result.from_cache
    assert result.key == expected_key
    meta = ais.ApkCache().read_meta(expected_key)
    assert [s["name"] for s in meta["splits"]] == ["base.apk", "split.apk"]
    assert meta["version_code"] == 3
    assert "androguard" in meta["tool_versions"]
    assert "created_at" in meta


def test_static_overview_dont_cache_switch(fake_adb, cache_root, monkeypatch, tmp_path):
    fake_adb({})
    monkeypatch.setattr(ais, "androguard_available", lambda: True)
    monkeypatch.setattr(ais, "_pull_apks", _fake_pull(tmp_path))
    monkeypatch.setattr(ais, "build_apk_overview", lambda p: {"schema": 1})

    service = ais.AppInfoService(use_cache=False)
    result = service.static_overview(PKG)

    assert result.ok
    assert result.overview == {"schema": 1}
    assert not cache_root.exists()


def test_static_overview_reports_missing_androguard(fake_adb, cache_root, monkeypatch):
    fake_adb({})
    monkeypatch.setattr(ais, "androguard_available", lambda: False)
    result = ais.get_static_overview(PKG)
    assert not result.ok
    assert "androguard" in result.reason


def test_record_and_load_insight_result(cache_root, tmp_path):
    result_file = tmp_path / "dexray_app.json"
    insight = {
        "apk_overview": {
            "general_info": {
                "package_name": PKG,
                "android_version_name": "1.2",
                "android_version_code": "12",
            },
            "native_libs": ["lib/arm64-v8a/libflutter.so"],
        },
        "apkid_analysis": {"files": [], "raw_output": "x" * 1000},
        "library_detection": {"detected_libraries": [{"name": "RootBeer", "x": 1}]},
    }
    key = ais.record_insight_result(
        [H1], insight, result_file=str(result_file), insight_version="2.0.0"
    )

    assert key == H1
    meta = ais.ApkCache().read_meta(H1)
    assert meta["package"] == PKG
    assert meta["version_name"] == "1.2"
    assert meta["insight"]["version"] == "2.0.0"
    summary = meta["insight"]["summary"]
    assert "raw_output" not in summary["apkid_analysis"]
    assert summary["library_detection"]["detected_libraries"][0]["name"] == "RootBeer"
    # Result file gone -> summary is served; present -> full file.
    assert ais.load_insight_results(meta) == summary
    result_file.write_text(json.dumps({"full": True}))
    assert ais.load_insight_results(meta) == {"full": True}
    # Don't-cache switch: nothing recorded.
    assert (
        ais.record_insight_result([H2], insight, cache=ais.ApkCache(enabled=False))
        is None
    )


# ---------------------------------------------------------------------------
# NSC parsing
# ---------------------------------------------------------------------------

NSC_XML = """\
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">legacy.example.com</domain>
  </domain-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">AAAA</pin>
      <pin digest="SHA-256">BBBB</pin>
    </pin-set>
  </domain-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
"""


class _FakeApk:
    def __init__(self, attrs):
        self.attrs = attrs

    def get_attribute_value(self, tag, name):
        return self.attrs.get(name)


def test_nsc_facts(monkeypatch):
    from lxml import etree

    root = etree.fromstring(NSC_XML.encode())
    monkeypatch.setattr(ais, "_resolve_nsc_xml", lambda apk: (root, "res/xml/n.xml"))
    facts = ais._nsc_facts(_FakeApk({"networkSecurityConfig": "@7F150001"}), 34)

    assert facts["present"]
    assert facts["cleartext_base"] is False
    assert facts["cleartext_domains"] == ["legacy.example.com"]
    assert facts["pin_sets"] == [
        {"domains": ["api.example.com"], "pins": 2, "expiration": "2027-01-01"}
    ]
    assert facts["trust_user_ca"] is False
    assert facts["trust_user_ca_debug_only"]


def test_nsc_defaults_without_config(monkeypatch):
    monkeypatch.setattr(ais, "_resolve_nsc_xml", lambda apk: (None, None))
    old = ais._nsc_facts(_FakeApk({"usesCleartextTraffic": "true"}), 23)
    assert old["trust_user_ca"] is True
    assert old["uses_cleartext_traffic"] is True
    assert ais._nsc_facts(_FakeApk({}), 30)["trust_user_ca"] is False


# ---------------------------------------------------------------------------
# Suspected defences
# ---------------------------------------------------------------------------

INSIGHT_RESULTS = {
    "apkid_analysis": {
        "files": [
            {
                "filename": "app.apk!classes.dex",
                "matches": {
                    "anti_vm": ["Build.FINGERPRINT check", "Build.MODEL check"],
                    "anti_debug": ["Debug.isDebuggerConnected() check"],
                    "obfuscator": ["DexGuard"],
                    "compiler": ["r8"],
                },
            },
            {"filename": "app.apk!classes2.dex", "matches": {"packer": ["Jiagu"]}},
        ]
    },
    "library_detection": {
        "detected_libraries": [
            {"name": "RootBeer", "package_name": "com.scottyab.rootbeer"},
            {"name": "OkHttp", "package_name": "okhttp3"},
            {"name": "Talsec freeRASP", "package_name": "com.aheaditec.talsec"},
        ]
    },
}


def test_suspect_defences_from_all_sources():
    overview = {
        "native_libs": ["libflutter.so", "libnss3.so", "libpairipcore.so", "libapp.so"],
        "nsc": {
            "present": True,
            "pin_sets": [{"domains": ["api.example.com"], "pins": 2}],
            "cleartext_domains": ["legacy.example.com"],
            "trust_user_ca": True,
        },
    }
    defences = {d.id: d for d in ais.suspect_defences(overview, INSIGHT_RESULTS)}

    assert defences["apkid:anti_vm"].routes == ["b6"]
    assert len(defences["apkid:anti_vm"].evidence) == 2
    assert defences["apkid:anti_debug"].routes == ["b4"]
    assert defences["apkid:packer"].routes == ["v"]
    assert "apkid:compiler" not in defences
    assert defences["lib:rootbeer"].routes == ["b2"]
    assert defences["lib:freerasp"].category == "rasp"
    assert set(defences["lib:freerasp"].routes) >= {"b2", "b3", "b4", "b5", "b6"}
    assert defences["lib:pairip"].routes == ["b5"]  # from libpairipcore.so
    assert defences["native:flutter_tls"].routes == ["h"]
    assert "b1" in defences["native:flutter_tls"].hint
    assert defences["native:nss_tls"].routes == ["h"]
    assert defences["nsc:pinning"].routes[0] == "b1"
    assert defences["nsc:cleartext"].weakness
    assert defences["nsc:user_ca"].weakness
    assert all(d.status == "suspected (static)" for d in defences.values())
    ordered = ais.suspect_defences(overview, INSIGHT_RESULTS)
    assert not ordered[0].weakness
    assert ordered[-1].weakness  # defences first


def test_suspect_defences_tolerates_missing_and_odd_inputs():
    assert ais.suspect_defences(None, None) == []
    assert ais.suspect_defences({}, {"apkid_analysis": None}) == []
    # Insight 2.0.0 full-hit payload shape is unwrapped.
    wrapped = ais.suspect_defences({}, {"main": INSIGHT_RESULTS, "security": None})
    assert any(d.id == "lib:rootbeer" for d in wrapped)
    # Insight's native list (paths) is a fallback for the overview's.
    from_insight = ais.suspect_defences(
        {}, {"apk_overview": {"native_libs": ["lib/arm64-v8a/libcronet.119.so"]}}
    )
    assert [d.id for d in from_insight] == ["native:cronet_tls"]


@pytest.mark.parametrize(
    "protections",
    [
        [
            {
                "name": "Play Integrity",
                "category": "integrity",
                "evidence": ["IntegrityManager"],
            }
        ],
        {"Play Integrity": {"category": "attestation"}},
        {"protections": [{"name": "Play Integrity", "type": "integrity"}]},
        ["Play Integrity"],
    ],
)
def test_suspect_defences_reads_insight_detected_protections(protections):
    defences = ais.suspect_defences({}, {"detected_protections": protections})
    (item,) = defences
    assert item.id == "lib:play_integrity"  # merged with the library row
    assert item.routes == ["b5"]
    assert item.source == "insight_protections"


#: Insight 2.0.0 shape: tracker_analysis.detected_protections.
TRACKER_PROTECTIONS = {
    "tracker_analysis": {
        "detected_protections": [
            {
                "id": "rootbeer",
                "name": "RootBeer",
                "category": "Root Detection",
                "defeats": ["root"],
                "confidence": "high",
                "matched_classes": ["com.scottyab.rootbeer.RootBeer"],
                "matched_libs": ["libtoolChecker.so"],
            },
            {
                "id": "appdome",
                "name": "Appdome",
                "category": "RASP",
                "defeats": ["root", "frida", "debug", "emulator", "integrity", "ssl"],
                "confidence": "medium",
                "matched_classes": [],
                "matched_libs": ["libloader.so"],
            },
            {
                "id": "acme_shield",
                "name": "Acme Shield",
                "category": "Anti-Tamper",
                "defeats": ["frida", "debug"],
            },
        ]
    },
    "library_detection": {"detected_libraries": [{"name": "RootBeer"}]},
}


def test_suspect_defences_reads_tracker_detected_protections():
    defences = {d.id: d for d in ais.suspect_defences({}, TRACKER_PROTECTIONS)}

    rootbeer = defences["lib:rootbeer"]  # library + Insight merged into one row
    assert rootbeer.routes == ["b2"]
    assert "Insight class: com.scottyab.rootbeer.RootBeer" in rootbeer.evidence
    assert "library detected: RootBeer" in rootbeer.evidence
    assert "Insight confidence: high" in rootbeer.evidence
    appdome = defences["lib:appdome"]
    assert appdome.category == "rasp"
    assert set(appdome.routes) == {"b1", "b2", "b3", "b4", "b5", "b6"}
    custom = defences["insight:acme_shield"]
    assert custom.routes == ["b3", "b4"]
    assert custom.status == "suspected (static)"


def test_insight_summary_keeps_tracker_protections(cache_root):
    ais.record_insight_result([H3], TRACKER_PROTECTIONS)
    meta = ais.ApkCache().read_meta(H3)
    summary = ais.load_insight_results(meta)
    assert {d.id for d in ais.suspect_defences({}, summary)} >= {
        "lib:rootbeer",
        "lib:appdome",
        "insight:acme_shield",
    }


def test_defences_to_dict_is_json_ready():
    (item,) = ais.suspect_defences({"native_libs": ["libnss3.so"]})
    assert json.loads(json.dumps(item.to_dict()))["routes"] == ["h"]


# ---------------------------------------------------------------------------
# static_analysis: result paths, Insight 1.0 vs 2.0, cache recording
# ---------------------------------------------------------------------------

INSIGHT_MAIN = {
    "apk_overview": {
        "general_info": {"package_name": PKG},
        "components": {
            "activities": ["a1", "a2"],
            "exported_activities": ["a1"],
            "services": ["s1"],
            "receivers": [],
            "providers": [],
        },
        "permissions": {
            "declared_permissions": [],
            "permissions": ["p1", "p2", "p3"],
        },
    },
    "apkid_analysis": {},
}


def test_insight_counts_nested_and_legacy_shapes():
    assert static_analysis._insight_counts(INSIGHT_MAIN) == {
        "permissions": 3,
        "activities": 2,
        "services": 1,
        "receivers": 0,
    }
    flat = {"permissions": ["x"], "activities": ["y", "z"]}
    assert static_analysis._insight_counts(flat)["activities"] == 2
    assert static_analysis._insight_counts({})["permissions"] == 0


class _FakeConfiguration:
    DEFAULT_CONFIG = {"caching": {"enabled": True, "cache_dir": None}}

    def __init__(self, config_dict=None):
        self.config_dict = config_dict


def _analyzer(monkeypatch, tmp_path, fake_asam):
    monkeypatch.setattr(static_analysis, "asam", fake_asam)
    analyzer = static_analysis.StaticAnalysis(adb=SimpleNamespace())
    analyzer._analysis_config["verbose_output"] = False
    monkeypatch.setattr(
        analyzer,
        "_get_toolbox",
        lambda: SimpleNamespace(mark_tool_used=lambda *a, **k: None),
    )
    monkeypatch.chdir(tmp_path)
    return analyzer


def test_insight2_gets_cache_dir_and_dict_results_are_handled(
    monkeypatch, tmp_path, cache_root
):
    seen = {}

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        seen["caching"] = config.config_dict["caching"]
        # Insight 2.0.0 full-hit cache re-run returns a plain dict.
        return {"main": INSIGHT_MAIN, "security": None}, "", ""

    fake_asam = SimpleNamespace(
        Configuration=_FakeConfiguration,
        start_apk_static_analysis_new=start_new,
        start_apk_static_analysis=lambda **k: pytest.fail("legacy path used"),
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")

    ok = analyzer._run_dexray_analysis(
        str(apk), "app", str(tmp_path) + "/", time.time(), other_split_sha256s=[]
    )

    assert ok
    assert seen["caching"] == {
        "enabled": True,
        "cache_dir": str(cache_root / "insight"),
    }
    assert analyzer.last_results["analysis_results"] == INSIGHT_MAIN
    key = ais.sha256_file(apk)
    meta = ais.ApkCache().read_meta(key)
    assert meta["package"] == PKG
    assert meta["insight"]["cache_dir"] == str(cache_root / "insight")


def test_insight1_uses_legacy_call(monkeypatch, tmp_path, cache_root):
    class Results:
        def to_dict(self):
            return INSIGHT_MAIN

        def to_json(self):
            return json.dumps(INSIGHT_MAIN)

    calls = []
    fake_asam = SimpleNamespace(
        Configuration=type("Cfg", (), {"DEFAULT_CONFIG": {"modules": {}}}),
        start_apk_static_analysis_new=lambda *a, **k: pytest.fail("new path used"),
        start_apk_static_analysis=lambda **k: calls.append(k) or (Results(), "", ""),
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    analyzer._analysis_config["use_cache"] = False

    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(tmp_path) + "/", time.time(), other_split_sha256s=[]
    )
    assert calls
    assert calls[0]["apk_file_path"] == str(apk)
    assert not cache_root.exists()  # don't-cache switch honoured


def test_device_mode_parses_split_pm_path(monkeypatch, tmp_path, cache_root):
    fake_asam = SimpleNamespace(
        Configuration=type("Cfg", (), {"DEFAULT_CONFIG": {}}),
        start_apk_static_analysis=lambda **k: ({"main": INSIGHT_MAIN}, "", ""),
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path) + "/")
    commands = []

    def send(command):
        commands.append(command)
        if "pm path" in command:
            return PM_PATH, ""
        if command.startswith("pull "):
            (tmp_path / "dexray_insight" / f"{PKG}.apk").write_bytes(b"base")
            return "1 file pulled", ""
        if "sha256sum" in command:
            return SHA_OUT, ""
        return "", ""

    monkeypatch.setattr(analyzer, "_send_adb_command", send)
    monkeypatch.setattr(
        analyzer,
        "_get_toolbox",
        lambda: SimpleNamespace(
            get_spotlight_application=lambda: PKG,
            mark_tool_used=lambda *a, **k: None,
        ),
    )

    assert analyzer._analyze_device_apk(time.time())
    pull = next(c for c in commands if c.startswith("pull "))
    assert "/base.apk" in pull
    assert "split_config" not in pull
    key = ais.compute_apk_key([ais.hashlib.sha256(b"base").hexdigest(), H2])
    assert ais.ApkCache().read_meta(key)["insight"]["cache_dir"] is None
