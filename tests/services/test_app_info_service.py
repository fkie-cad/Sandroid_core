"""Tests for :mod:`sandroid.services.app_info_service` (no device needed).

Device output is replayed from recorded-format fixture strings: ``Adb``'s
classmethods are replaced on ``sandroid.core.adb.Adb`` with ``staticmethod``
fakes (same convention as ``tests/ai/tools/test_app_query.py``).
"""

import hashlib
import json
import os
import re
import shlex
import stat
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
    isForeground=true foregroundId=1001 types=00000048 foregroundNoti=Notification(channel=loc pri=0)
    createTime=-5m2s ago startingBgTimeout=--
  * ServiceRecord{5a5a5a5 u0 com.example.app/.SyncService}
    intent={cmp=com.example.app/.SyncService}
    app=ProcessRecord{c1d2e3f 4321:com.example.app/u0a150}
    createTime=-1m ago startingBgTimeout=--
  * ServiceRecord{6b6b6b6 u0 com.other.app/.Svc}
    isForeground=true foregroundId=7 types=00000001 foregroundNoti=Notification()
"""

#: Older ``foregroundServiceType=`` spelling (API 30/31).
SERVICES_API30 = """\
  * ServiceRecord{abc1234 u0 com.example.app/.PlayerService}
    app=ProcessRecord{def5678 999:com.example.app:player/u0a150}
    isForeground=true foregroundId=5 foregroundNoti=Notification(channel=media)
    foregroundServiceType=0x00000002
"""

#: footprint_script output: du CE, du DE, du external, ls CE prefs, ls CE
#: databases, ls DE prefs, ls DE databases.
FOOTPRINT_ROOT = f"""\
51234\t/data/data/{PKG}
@@SANDROID_SEP@@
16\t/data/user_de/0/{PKG}
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
@@SANDROID_SEP@@
ls: /data/user_de/0/{PKG}/shared_prefs: No such file or directory
@@SANDROID_SEP@@
ls: /data/user_de/0/{PKG}/databases: No such file or directory
"""

FOOTPRINT_NOROOT = f"""\
du: /data/data/{PKG}: Permission denied
@@SANDROID_SEP@@
du: /data/user_de/0/{PKG}: Permission denied
@@SANDROID_SEP@@
du: /sdcard/Android/data/{PKG}: No such file or directory
@@SANDROID_SEP@@
ls: /data/data/{PKG}/shared_prefs: Permission denied
@@SANDROID_SEP@@
ls: /data/data/{PKG}/databases: Permission denied
@@SANDROID_SEP@@
ls: /data/user_de/0/{PKG}/shared_prefs: Permission denied
@@SANDROID_SEP@@
ls: /data/user_de/0/{PKG}/databases: Permission denied
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


@pytest.fixture(autouse=True)
def _fresh_split_hash_memo(monkeypatch):
    monkeypatch.setattr(ais, "_SPLIT_HASH_MEMO", {})


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


class _ManifestApk:
    """androguard-like APK: ``(tag, name, maxSdkVersion)`` requests."""

    REQUESTS = [
        ("uses-permission", "android.permission.INTERNET", None),
        ("uses-permission", "android.permission.WRITE_EXTERNAL_STORAGE", "28"),
        ("uses-permission", "android.permission.BLUETOOTH", "30"),
        ("uses-permission", "android.permission.CAMERA", "0"),
        ("uses-permission-sdk-23", "android.permission.ACCESS_FINE_LOCATION", None),
        ("uses-permission-sdk-23", "android.permission.INTERNET", None),
    ]

    def __init__(self, path=None):
        self.path = path

    def find_tags(self, tag_name):
        return [r for r in self.REQUESTS if r[0] == tag_name]

    def get_value_from_tag(self, tag, attribute):
        return {"name": tag[1], "maxSdkVersion": tag[2]}[attribute]

    def get_permissions(self):
        # androguard reads <uses-permission> only (plus a name the tag scan
        # cannot see here, to show nothing the parser reports is lost)
        return [r[1] for r in self.REQUESTS if r[0] == "uses-permission"] + [
            "android.permission.VIBRATE"
        ]

    def get_attribute_value(self, tag, name):
        return None

    def get_files(self):
        return []


def test_requested_permission_entries_read_both_tags():
    entries = ais.requested_permission_entries(_ManifestApk())
    assert [(e["tag"], e["name"], e["max_sdk_version"]) for e in entries] == [
        ("uses-permission", "android.permission.INTERNET", None),
        ("uses-permission", "android.permission.WRITE_EXTERNAL_STORAGE", 28),
        ("uses-permission", "android.permission.BLUETOOTH", 30),
        ("uses-permission", "android.permission.CAMERA", None),  # 0 = no limit
        ("uses-permission-sdk-23", "android.permission.ACCESS_FINE_LOCATION", None),
        ("uses-permission-sdk-23", "android.permission.INTERNET", None),
        ("uses-permission", "android.permission.VIBRATE", None),
    ]


def test_build_apk_overview_records_sdk23_requests(monkeypatch, tmp_path):
    monkeypatch.setattr(ais, "androguard_apk_class", lambda: _ManifestApk)
    overview = ais.build_apk_overview([str(tmp_path / "base.apk")])
    assert "android.permission.ACCESS_FINE_LOCATION" in overview["permissions"]
    assert len(overview["permissions"]) == 6  # unique names, both tags
    assert len(overview["requested_permissions"]) == 7
    assert ais.manifest_permission_names(overview) == [
        "android.permission.INTERNET",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.BLUETOOTH",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.VIBRATE",
    ]


_WRITE = "android.permission.WRITE_EXTERNAL_STORAGE"
_BT = "android.permission.BLUETOOTH"


@pytest.mark.parametrize(
    ("api_level", "dropped"),
    [
        # <uses-permission-sdk-23> applies from API 23 on (INTERNET stays:
        # it is also requested with the plain tag)
        (22, {"android.permission.ACCESS_FINE_LOCATION"}),
        (28, set()),  # maxSdkVersion 28 still applies on API 28
        (29, {_WRITE}),
        (35, {_WRITE, _BT}),
    ],
)
def test_effective_permission_names_drop_max_sdk_below_the_device(api_level, dropped):
    overview = {
        "requested_permissions": ais.requested_permission_entries(_ManifestApk())
    }
    names = set(ais.manifest_permission_names(overview))
    kept = ais.effective_permission_names(overview, api_level)
    assert set(kept) == names - dropped
    assert len(kept) == len(set(kept))


def test_permission_counts_prefer_dumpsys_and_fall_back_to_the_manifest():
    overview = {
        "requested_permissions": ais.requested_permission_entries(_ManifestApk())
    }
    state = ais.parse_permission_state(DUMPSYS_PACKAGE_API30, PKG)
    requested = sum(1 for g in state.permissions if g.requested)
    assert ais.permission_counts(state, overview) == (requested, 6)
    assert ais.permission_counts(state, None) == (requested, None)
    # No requested permission readable: the manifest's effective requests
    # on the device's API level stand in.
    empty = ais.PermissionState(package=PKG, ok=False, reason="x", api_level=35)
    assert ais.permission_counts(empty, overview) == (4, 6)
    empty.api_level = None
    assert ais.permission_counts(empty, overview) == (None, 6)


def test_get_permission_state_reads_the_api_level_only_when_needed(fake_adb):
    fake = fake_adb(
        {
            "dumpsys package": DUMPSYS_PACKAGE_API30,
            "list permissions": PM_DANGEROUS,
            "getprop ro.build.version.sdk": "35\n",
        }
    )
    state = ais.get_permission_state(PKG, serial="emulator-5556")
    assert state.api_level is None
    assert not any("getprop" in c for c, _s in fake.calls)
    fake = fake_adb({"dumpsys package": "", "getprop ro.build.version.sdk": "35\n"})
    state = ais.get_permission_state(PKG, serial="emulator-5556")
    assert not state.ok
    assert state.api_level == 35
    assert all(serial == "emulator-5556" for _c, serial in fake.calls)


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
    ops = {o.op: o for o in ais.parse_appops(APPOPS_API30)}

    coarse = ops["COARSE_LOCATION"]
    assert coarse.uid_mode == "foreground"
    assert coarse.package_mode == "allow"
    assert coarse.mode == "foreground"  # uid mode wins
    # Unprefixed line right after "Uid mode:" stays in uid scope.
    assert ops["LEGACY_STORAGE"].uid_mode == "allow"
    assert ops["LEGACY_STORAGE"].package_mode is None
    assert coarse.last_access == "+3m10s510ms ago"
    assert coarse.last_access_ago_s == 190.51
    assert coarse.permission == "android.permission.ACCESS_COARSE_LOCATION"
    camera = ops["CAMERA"]
    assert camera.mode == "ignore"
    assert camera.last_reject_ago_s == 3720.0
    assert camera.last_access is None
    clip = ops["READ_CLIPBOARD"]
    assert clip.permission is None
    assert clip.last_access_ago_s == 303.0
    storage = ops["READ_EXTERNAL_STORAGE"]
    assert storage.duration_s == 0.012
    # No state markers in this format.
    assert clip.foreground is None
    assert clip.background is None


def test_appops_api34_running_and_reject():
    ops = {o.op: o for o in ais.parse_appops(APPOPS_API34)}

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
    ops = {o.op: o for o in ais.parse_appops(APPOPS_API36_BLOCK)}

    coarse = ops["COARSE_LOCATION"]
    assert (coarse.uid_mode, coarse.package_mode, coarse.mode) == (
        "foreground",
        None,
        "foreground",
    )
    clip = ops["READ_CLIPBOARD"]
    assert clip.mode == "allow"
    assert clip.last_access == "2026-05-01 12:00:00.123"  # most recent tag
    assert clip.last_access_ago_s == 303.123
    assert clip.access_states == ["top-s", "bg-s"]
    assert clip.foreground is True
    assert clip.background is True
    camera = ops["CAMERA"]
    assert camera.mode == "ignore"
    assert camera.reject_states == ["bg-s"]
    assert camera.last_reject_ago_s == 900.0
    fine = ops["FINE_LOCATION"]
    assert fine.duration_s == 2.5
    assert fine.foreground is True
    assert fine.background is False


#: ``cmd appops get``: "Uid mode: " precedes only the FIRST uid op.
APPOPS_UID_BLOCK = """\
Uid mode: COARSE_LOCATION: foreground
FINE_LOCATION: foreground
CAMERA: ignore
CAMERA: allow; time=+5m ago
FINE_LOCATION: allow; time=+1m ago; duration=+3s
"""


def test_appops_uid_block_without_prefix_and_effective_mode():
    ops = {o.op: o for o in ais.parse_appops(APPOPS_UID_BLOCK)}

    fine = ops["FINE_LOCATION"]
    assert (fine.uid_mode, fine.package_mode, fine.mode) == (
        "foreground",
        "allow",
        "foreground",
    )
    camera = ops["CAMERA"]
    assert (camera.uid_mode, camera.package_mode) == ("ignore", "allow")
    assert camera.mode == "ignore"  # effective: uid mode wins
    assert camera.last_access_ago_s == 300.0
    assert ops["COARSE_LOCATION"].package_mode is None


def test_appops_running_start_line_sets_running():
    text = (
        "Package com.example.app:\n"
        "  CAMERA (allow):\n"
        "    null=[\n"
        "      Access: [fgsvcl-s] 2026-05-01 12:00:00.000 (-2s)\n"
        "    ]\n"
        "    Running start at: +2s\n"
        "  RECORD_AUDIO (allow):\n"
        "      Access: [top-s] 2026-05-01 11:00:00.000 (-1h)\n"
    )
    ops = {o.op: o for o in ais.parse_appops(text)}
    assert ops["CAMERA"].running is True
    assert ops["CAMERA"].foreground is True  # fgsvcl = location FGS state
    assert ops["RECORD_AUDIO"].running is False


def test_appops_op_code_order_ends_uid_block():
    # COARSE_LOCATION (op 0) after CAMERA (op 26): codes restart -> package.
    text = "Uid mode: CAMERA: ignore\nCOARSE_LOCATION: allow\n"
    ops = {o.op: o for o in ais.parse_appops(text)}
    assert ops["CAMERA"].uid_mode == "ignore"
    assert ops["COARSE_LOCATION"].uid_mode is None
    assert ops["COARSE_LOCATION"].package_mode == "allow"
    # Increasing codes stay in the uid block.
    ops = {
        o.op: o
        for o in ais.parse_appops("Uid mode: CAMERA: ignore\nRECORD_AUDIO: deny\n")
    }
    assert ops["RECORD_AUDIO"].uid_mode == "deny"


def test_appops_repeated_op_ends_uid_block():
    text = "Uid mode: CAMERA: ignore\nRECORD_AUDIO: deny\nCAMERA: allow\n"
    ops = {o.op: o for o in ais.parse_appops(text)}
    assert ops["CAMERA"].uid_mode == "ignore"
    assert ops["CAMERA"].package_mode == "allow"
    assert ops["RECORD_AUDIO"].uid_mode == "deny"


def test_appops_access_line_with_proxy_suffix():
    text = (
        "Package com.example.app:\n"
        "  RECORD_AUDIO (allow):\n"
        "    null=[\n"
        "      Access: [fg-tp] 2026-05-01 12:00:00.000 (-2m3s) duration=+1s "
        "proxy[uid=1000, pkg=com.google.android.gms, attributionTag=null]\n"
        "    ]\n"
    )
    (audio,) = ais.parse_appops(text)
    assert audio.last_access_ago_s == 123.0
    assert audio.duration_s == 1.0
    assert audio.proxy_packages == ["com.google.android.gms"]
    assert audio.foreground is True


def test_get_appops_prefers_dumpsys(fake_adb):
    fake = fake_adb({"dumpsys appops": APPOPS_API36_BLOCK})
    state = ais.get_appops(PKG, serial="emulator-5554")

    assert state.ok
    assert state.source == "dumpsys appops"
    assert [c for c, _s in fake.calls] == [f"shell dumpsys appops --package {PKG}"]
    assert {s for _c, s in fake.calls} == {"emulator-5554"}


def test_get_appops_falls_back_to_cmd_appops(fake_adb):
    fake = fake_adb({"dumpsys appops": "", "cmd appops": APPOPS_API30})
    state = ais.get_appops(PKG)

    assert state.ok
    assert state.source == "cmd appops get"
    assert [c for c, _s in fake.calls] == [
        f"shell dumpsys appops --package {PKG}",
        f"shell cmd appops get {PKG}",
    ]


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
    assert (result.private_kb, result.de_kb, result.external_kb) == (51234, 16, 2048)
    assert result.private_total_kb == 51250
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
    probes = [c for c, _s in fake.calls if "du -sk" not in c and "dataDir" not in c]
    assert len(probes) == 3


def test_footprint_wraps_script_for_su(fake_adb):
    fake = fake_adb({"su -c": "uid=0(root)", "du -sk": FOOTPRINT_ROOT})
    result = ais.get_data_footprint(PKG)

    assert result.root_method == "su -c"
    assert "su -c " in fake.calls[-1][0]
    assert "du -sk" in fake.calls[-1][0]


def test_footprint_without_root_ignores_tiny_du_size(fake_adb):
    noisy = FOOTPRINT_NOROOT.replace(
        f"du: /data/data/{PKG}: Permission denied",
        f"du: /data/data/{PKG}/cache: Permission denied\n8\t/data/data/{PKG}",
    )
    fake_adb({"du -sk": noisy, "id": "uid=2000(shell)"})
    result = ais.get_data_footprint(PKG)
    assert result.private_kb is None
    assert result.private_reason == "root required (enable adb root)"


def test_footprint_timeout_reported(monkeypatch):
    timeouts = []

    def slow(command, serial=None, timeout=30):
        timeouts.append(timeout)
        if "du -sk" in command:
            return "", f"Command timed out after {timeout:g} seconds"
        return "uid=0(root)", ""

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(slow))
    result = ais.get_data_footprint(PKG)
    assert result.reason == "timed out after 120s (du)"
    assert timeouts[-1] == ais.FOOTPRINT_TIMEOUT_SECONDS


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
        ("00000008", ["location"]),
        ("00000048", ["location", "camera"]),  # %08X: hex, not decimal 48
        ("00000010", ["connectedDevice"]),
        ("FFFFFFFF", ["manifest"]),
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

    overview = {
        "schema": ais.OVERVIEW_SCHEMA,
        "package": PKG,
        "androguard_version": ais._androguard_version(),
        "requested_permissions": [],
    }
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


def test_cache_overview_without_an_added_key_is_a_miss(cache_root):
    """An entry from before ``requested_permissions`` is rebuilt here."""
    cache = ais.ApkCache()
    overview = {
        "schema": ais.OVERVIEW_SCHEMA,
        "androguard_version": ais._androguard_version(),
    }
    cache.write_entry(H1, overview=overview)
    assert cache.read_overview(H1) is None
    cache.write_entry(H1, overview={**overview, "requested_permissions": []})
    assert cache.read_overview(H1) is not None


def test_cache_other_androguard_version_is_stale(cache_root, monkeypatch):
    cache = ais.ApkCache()
    overview = {
        "schema": ais.OVERVIEW_SCHEMA,
        "androguard_version": "3.0.0",
        "requested_permissions": [],
    }
    cache.write_entry(H1, overview=overview)
    monkeypatch.setattr(ais, "_androguard_version", lambda: "4.1.3")
    assert cache.read_overview(H1) is None
    # Without androguard here, any version is served (cannot rebuild anyway).
    monkeypatch.setattr(ais, "_androguard_version", lambda: None)
    assert cache.read_overview(H1) == overview


def test_cache_files_are_share_readable(cache_root, monkeypatch):
    umask = os.umask(0o022)  # test-local, single-threaded
    os.umask(umask)
    os.umask(0o022)
    try:
        # The service itself must neither read the umask nor use mkstemp.
        monkeypatch.setattr(os, "umask", lambda *_a: pytest.fail("umask read"))
        monkeypatch.setattr(
            ais.tempfile, "mkstemp", lambda *a, **k: pytest.fail("mkstemp")
        )
        ais.ApkCache().write_entry(H1, overview={"schema": 1}, meta_updates={"a": 1})
    finally:
        monkeypatch.undo()
        os.umask(umask)
    for name in ("meta.json", "overview.json"):
        mode = stat.S_IMODE((cache_root / "apk" / H1 / name).stat().st_mode)
        assert mode == 0o644  # 0o666 under the umask (mkstemp alone gives 0600)
    assert sorted(p.name for p in (cache_root / "apk" / H1).iterdir()) == [
        "meta.json",
        "overview.json",
    ]


def test_cache_readers_tolerate_malformed_json(cache_root):
    entry = cache_root / "apk" / H1
    entry.mkdir(parents=True)
    (entry / "meta.json").write_text("[1, 2]")
    (entry / "overview.json").write_text("{not json")
    (cache_root / "apk" / "not-a-key").mkdir()
    cache = ais.ApkCache()
    assert cache.read_meta(H1) is None
    assert cache.read_overview(H1) is None
    assert cache.find(PKG) == []
    assert ais.load_insight_results({"insight": "x"}) is None
    assert ais.load_insight_results({"insight": {"summary": [1]}}) is None


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
    assert [p.name for p in entry.iterdir()] == ["meta.json"]  # no stale leftovers


def test_cache_lock_release_keeps_foreign_lock(cache_root):
    cache = ais.ApkCache()
    with cache._locked(H1) as entry:
        lock = entry / ".lock"
        lock.write_text("someone-else")  # e.g. our lock was broken and re-taken
    assert lock.read_text() == "someone-else"


def test_cache_stale_break_restores_a_fresh_lock(cache_root, monkeypatch):
    cache = ais.ApkCache(stale_lock_after=60)
    entry = cache_root / "apk" / H1
    entry.mkdir(parents=True)
    lock = entry / ".lock"
    lock.write_text("new-owner")
    old = time.time() - 120
    real_stat = Path.stat

    def stale_once(self, *a, **k):  # stat says stale, then the owner refreshes
        if self.name == ".lock":
            return SimpleNamespace(st_mtime=old)
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", stale_once)
    cache._break_if_stale(lock)
    assert lock.read_text() == "new-owner"  # renamed aside, verified, linked back
    assert [p.name for p in entry.iterdir()] == [".lock"]


def test_cache_lock_times_out_on_stat_errors(cache_root, monkeypatch):
    cache = ais.ApkCache(lock_timeout=0.2)
    entry = cache_root / "apk" / H1
    entry.mkdir(parents=True)
    (entry / ".lock").write_text("x")

    real_stat = Path.stat

    def broken_stat(self, *a, **k):
        if self.name == ".lock":
            raise PermissionError("share hiccup")
        return real_stat(self, *a, **k)

    monkeypatch.setattr(Path, "stat", broken_stat)
    started = time.monotonic()
    with pytest.raises(ais.CacheLockTimeoutError):
        with cache._locked(H1):
            pass
    assert time.monotonic() - started < 2


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
    key = H1  # the config split (H2) is not part of the key
    ais.ApkCache().write_entry(
        key,
        overview={
            "schema": ais.OVERVIEW_SCHEMA,
            "native_libs": [],
            "androguard_version": ais._androguard_version(),
            "requested_permissions": [],
        },
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


def test_apk_key_ignores_config_splits():
    with_abi = [("/x/base.apk", H1), ("/x/split_config.arm64_v8a.apk", H2)]
    with_other_abi = [("/x/base.apk", H1), ("/x/split_config.x86_64.apk", H3)]
    assert ais.apk_key_for(with_abi) == ais.apk_key_for(with_other_abi) == H1
    feature = [("/x/base.apk", H1), ("/x/split_feature.apk", H2)]
    assert ais.apk_key_for(feature) == ais.compute_apk_key([H1, H2])


def test_split_hashes_are_memoized_per_install(fake_adb):
    fake = fake_adb(
        {
            "grep": "versionCode=7 minSdk=24\nlastUpdateTime=2026-05-01 10:00:00",
            "pm path": PM_PATH,
            "sha256sum": SHA_OUT,
        }
    )
    first = ais.device_split_hashes(PKG, "emulator-5554")
    second = ais.device_split_hashes(PKG, "emulator-5554")
    assert first == second
    assert sum("sha256sum" in c for c, _s in fake.calls) == 1
    # A different install identity (update) re-hashes.
    fake.answers["grep"] = "versionCode=8\nlastUpdateTime=2026-06-01 10:00:00"
    ais.device_split_hashes(PKG, "emulator-5554")
    assert sum("sha256sum" in c for c, _s in fake.calls) == 2


def _fake_pull(tmp_path):
    def pull(package, dest_dir, serial=None):
        pulled = []
        for name, data in (
            ("base.apk", b"base"),
            ("split.apk", b"split"),
            ("split_config.arm64_v8a.apk", b"abi"),
        ):
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
    assert [s["name"] for s in meta["splits"]] == [
        "base.apk",
        "split.apk",
        "split_config.arm64_v8a.apk",
    ]
    assert [s["config"] for s in meta["splits"]] == [False, False, True]
    assert "/data/app" not in json.dumps(meta)  # no device/local paths
    assert meta["version_code"] == 3
    assert "androguard" in meta["tool_versions"]
    assert "created_at" in meta


def test_static_overview_dont_cache_switch(fake_adb, cache_root, monkeypatch, tmp_path):
    fake_adb({})
    monkeypatch.setattr(ais, "androguard_available", lambda: True)
    monkeypatch.setattr(ais, "_pull_apks", _fake_pull(tmp_path))
    built = {"schema": ais.OVERVIEW_SCHEMA, "package": PKG}
    monkeypatch.setattr(ais, "build_apk_overview", lambda p: built)

    service = ais.AppInfoService(use_cache=False)
    result = service.static_overview(PKG)

    assert result.ok
    assert result.overview == built
    assert not cache_root.exists()


@pytest.mark.parametrize(
    "built",
    [
        {"schema": 2, "errors": ["base.apk: Bad magic number"], "splits": []},
        {"schema": 2, "package": PKG, "errors": ["split.apk manifest: boom"]},
    ],
)
def test_failed_decode_is_never_cached(
    built, fake_adb, cache_root, monkeypatch, tmp_path
):
    fake_adb({})
    monkeypatch.setattr(ais, "androguard_available", lambda: True)
    monkeypatch.setattr(ais, "_pull_apks", _fake_pull(tmp_path))
    monkeypatch.setattr(ais, "build_apk_overview", lambda p: built)

    result = ais.get_static_overview(PKG)

    assert result.reason.startswith("not cached: APK decode incomplete")
    assert result.ok is bool(built.get("package"))
    assert not (cache_root / "apk").exists()


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
        [H1],
        insight,
        result_file=str(result_file),
        insight_version="2.0.0",
        insight_cache_used=True,
        apk_md5="d" * 32,
    )

    assert key == H1
    meta = ais.ApkCache().read_meta(H1)
    assert meta["package"] == PKG
    assert meta["version_name"] == "1.2"
    assert meta["insight"]["version"] == "2.0.0"
    summary = meta["insight"]["summary"]
    assert "raw_output" not in summary["apkid_analysis"]
    assert summary["library_detection"]["detected_libraries"][0]["name"] == "RootBeer"
    # Only cache-relative references: no absolute/local paths in meta.json.
    assert str(tmp_path) not in json.dumps(meta)
    assert meta["insight"]["result_name"] == "dexray_app.json"
    assert meta["insight"]["cache"] == "insight"
    assert meta["insight"]["apk_md5"] == "d" * 32
    assert ais.load_insight_results(meta) == summary
    # A shared meta naming an existing absolute path is never followed.
    result_file.write_text(json.dumps({"full": True}))
    meta["insight"]["result_file"] = str(result_file)
    assert ais.load_insight_results(meta) == summary
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
    assert facts["trust_user_ca_debug_only"]  # not debuggable: not effective
    assert facts["debug_overrides_active"] is False


def _nsc(monkeypatch, xml, attrs=None, target=34, debuggable=False):
    from lxml import etree

    root = etree.fromstring(xml.encode())
    monkeypatch.setattr(ais, "_resolve_nsc_xml", lambda apk: (root, "res/xml/n.xml"))
    return ais._nsc_facts(_FakeApk(attrs or {}), target, debuggable)


def test_nsc_defaults_without_config(monkeypatch):
    monkeypatch.setattr(ais, "_resolve_nsc_xml", lambda apk: (None, None))
    old = ais._nsc_facts(_FakeApk({"usesCleartextTraffic": "true"}), 23)
    assert old["trust_user_ca"] is True
    assert old["uses_cleartext_traffic"] is True
    assert old["cleartext_effective"] is True
    modern = ais._nsc_facts(_FakeApk({}), 30)
    assert modern["trust_user_ca"] is False
    assert modern["cleartext_effective"] is False  # targetSdk >= 28 default


def test_nsc_overrides_uses_cleartext_traffic(monkeypatch):
    xml = '<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>'
    facts = _nsc(monkeypatch, xml, {"usesCleartextTraffic": "true"})
    assert facts["uses_cleartext_traffic"] is True
    assert facts["cleartext_effective"] is False
    assert facts["cleartext_source"] == "NSC base-config"
    ids = {d.id for d in ais.suspect_defences({"nsc": facts})}
    assert "nsc:cleartext" not in ids


def test_nsc_base_without_trust_anchors_old_target(monkeypatch):
    xml = '<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>'
    facts = _nsc(monkeypatch, xml, target=23)
    assert facts["trust_user_ca"] is True
    assert facts["trust_user_ca_source"].startswith("platform default")


def test_nsc_domain_scoped_user_ca_and_override_pins(monkeypatch):
    xml = """<network-security-config>
      <domain-config>
        <domain>staging.example.com</domain>
        <trust-anchors><certificates src="user" overridePins="true"/></trust-anchors>
        <pin-set><pin digest="SHA-256">AAAA</pin></pin-set>
      </domain-config>
    </network-security-config>"""
    facts = _nsc(monkeypatch, xml)
    assert facts["trust_user_ca"] is False
    assert facts["trust_user_ca_domains"] == ["staging.example.com"]
    assert facts["override_pins_scopes"] == ["staging.example.com"]
    defences = {d.id: d for d in ais.suspect_defences({"nsc": facts})}
    assert "nsc:user_ca" not in defences
    assert "staging.example.com" in defences["nsc:user_ca_scoped"].evidence[0]
    assert any("overridePins" in e for e in defences["nsc:pinning"].evidence)


def test_nsc_debug_overrides_apply_when_debuggable(monkeypatch):
    facts = _nsc(monkeypatch, NSC_XML, debuggable=True)
    assert facts["debug_overrides_active"] is True
    assert facts["trust_user_ca"] is True
    assert "debug-overrides" in facts["trust_user_ca_source"]


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

    # No code location: common in GMS/Firebase, so verify first, low confidence.
    assert defences["apkid:anti_vm"].routes == ["v", "b6"]
    assert defences["apkid:anti_vm"].confidence == "low"
    assert "likely benign" in defences["apkid:anti_vm"].title
    assert len(defences["apkid:anti_vm"].evidence) == 2
    assert defences["apkid:anti_debug"].routes == ["v", "b4"]
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


@pytest.mark.parametrize(
    ("match", "routes", "confidence"),
    [
        ("Build.FINGERPRINT check in Lcom/evil/Guard;", ["b6"], "medium"),
        ("Build.FINGERPRINT check in com.evil.guard.Checks", ["b6"], "medium"),
        ("Build.FINGERPRINT check in Lcom/google/android/gms/Foo;", ["v", "b6"], "low"),
        ("Build.MODEL check in androidx.test.Runner", ["v", "b6"], "low"),
    ],
)
def test_apkid_anti_vm_located_in_app_code(match, routes, confidence):
    insight = {
        "apkid_analysis": {
            "files": [{"filename": "classes.dex", "matches": {"anti_vm": [match]}}]
        }
    }
    (item,) = ais.suspect_defences({}, insight)
    assert item.routes == routes
    assert item.confidence == confidence


@pytest.mark.parametrize(
    ("libs", "ids"),
    [
        (["libssl.so", "libcrypto.so"], {"native:openssl_tls"}),
        (["libcrypto.so"], {"native:crypto_lib"}),
        (["libssl_helper.so", "libflutter_ext.so", "libnss3x.so"], set()),
        (["libconscrypt_jni.so"], {"native:conscrypt_tls"}),
    ],
)
def test_native_tls_exact_basenames(libs, ids):
    found = {d.id: d for d in ais.suspect_defences({"native_libs": libs})}
    assert set(found) == ids
    if "native:crypto_lib" in found:
        assert found["native:crypto_lib"].routes == []
        assert "TLS not implied" in found["native:crypto_lib"].hint
    if "native:openssl_tls" in found:
        assert "native lib libcrypto.so" in found["native:openssl_tls"].evidence


def test_suspect_defences_tolerate_malformed_shared_json():
    overview = {"native_libs": 5, "nsc": "x"}
    insight = {
        "apkid_analysis": {"files": "bad"},
        "library_detection": [1, "x"],
        "tracker_analysis": {"detected_protections": 7},
        "detected_protections": [{"name": "RootBeer", "defeats": "root"}],
        "apk_overview": [],
    }
    found = ais.suspect_defences(overview, insight)
    assert [d.id for d in found] == ["lib:rootbeer"]
    assert ais.suspect_defences("nope", ["nope"]) == []


@pytest.mark.parametrize(
    ("evidence", "confidence", "line"),
    [
        ("sdk_present", "low", "Insight: SDK present, may not be enforced"),
        ("entry_point", "high", "Insight: entry point referenced (likely enforced)"),
    ],
)
def test_insight_protection_evidence_kind(evidence, confidence, line):
    item = {
        "id": "rootbeer",
        "name": "RootBeer",
        "category": "Root Detection",
        "defeats": ["root"],
        "confidence": "high",
        "evidence": evidence,
    }
    (found,) = ais.suspect_defences(
        {}, {"tracker_analysis": {"detected_protections": [item]}}
    )
    assert found.confidence == confidence
    assert line in found.evidence
    if evidence == "sdk_present":
        assert found.hint.startswith("SDK present, may not be enforced")


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
    monkeypatch.setattr(
        static_analysis, "insight_work_root", lambda: tmp_path / "insight-work"
    )
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
    assert meta["insight"]["cache"] == "insight"
    assert meta["insight"]["apk_md5"] == hashlib.md5(b"apk-bytes").hexdigest()
    assert str(tmp_path) not in json.dumps(meta)


def test_insight1_uses_legacy_call(monkeypatch, tmp_path, cache_root):
    class Results:
        def to_dict(self):
            return INSIGHT_MAIN

        def to_json(self):
            return json.dumps(INSIGHT_MAIN)

    calls = []
    # An Insight without the configurable entry point gets the legacy call.
    fake_asam = SimpleNamespace(
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
    # Analysed from the run's own work folder (same file name and bytes).
    staged = Path(calls[0]["apk_file_path"])
    assert staged.name == apk.name
    assert staged.parent.parent == tmp_path / "insight-work"
    assert not cache_root.exists()  # don't-cache switch honoured


class _ProfileConfiguration:
    """An Insight >= 2.2 Configuration: takes ``profile``."""

    DEFAULT_CONFIG = {"caching": {"enabled": True, "cache_dir": None}}

    def __init__(self, config_dict=None, profile=None):
        self.config_dict = config_dict
        self.profile = profile


def test_profile_trackers_and_dirs_reach_a_profile_aware_insight(
    monkeypatch, tmp_path, cache_root
):
    seen = {}
    out_dir = tmp_path / "session" / "dexray_insight"

    def start_new(
        apk, config, print_results_to_terminal=False, verbose=False, output_dir=None
    ):
        seen["config"] = config
        seen["output_dir"] = output_dir
        work = config.config_dict["temporal_analysis"]["base_directory"]
        seen["work"] = work
        seen["apk"] = apk
        assert os.path.isdir(work)
        # Insight's per-run temporal folder and apktool_out next to the APK.
        (Path(work) / "dexray_app_2026").mkdir()
        (Path(apk).parent / "apktool_out").mkdir()
        main = Path(output_dir) / "dexray_app_T.json"
        main.parent.mkdir(parents=True, exist_ok=True)
        main.write_text("{}")
        return {"main": INSIGHT_MAIN, "security": None}, str(main), ""

    events = []
    monkeypatch.setattr(
        static_analysis.TaskOutput, "publish", lambda self: events.append(self)
    )
    fake_asam = SimpleNamespace(
        Configuration=_ProfileConfiguration, start_apk_static_analysis_new=start_new
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    analyzer._analysis_config.update(profile="privacy", run_tracker_analysis=False)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")

    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(out_dir) + "/", time.time(), other_split_sha256s=[]
    )

    config = seen["config"]
    assert config.profile == "privacy"
    # A profile-aware Insight gets the name, not Sandroid's fallback copy.
    assert "native_analysis" not in config.config_dict["modules"]
    assert config.config_dict["modules"]["tracker_analysis"]["enabled"] is False
    assert config.config_dict["temporal_analysis"]["cleanup_after_analysis"] is True
    definitions = config.config_dict["modules"]["library_detection"][
        "apktool_detection"
    ]
    assert ".dexray_insight" in definitions["libsmali_path"]
    assert seen["output_dir"] == str(out_dir) + "/"
    work_root = tmp_path / "insight-work"
    assert seen["work"] == str(work_root)  # stable root: same cache key every run
    assert Path(seen["apk"]).parent.parent == work_root  # analysed from a run folder
    # Our run folder is gone; Insight's own folder is Insight's to remove
    # (a concurrent run of the same APK may still be using one).
    assert [p.name for p in work_root.iterdir()] == ["dexray_app_2026"]
    assert list(tmp_path.glob("*.jsonl")) == []
    assert not (tmp_path / "temp_analysis").exists()
    assert analyzer.last_results["options"]["profile"] == "privacy"
    started = events[0]
    assert started.data["state"] == "started"
    assert started.data["profile"] == "privacy"
    assert started.data["trackers"] is False
    assert "privacy profile, trackers off" in started.message
    finished = events[-1]
    assert finished.data["state"] == "finished"
    assert finished.data["package"] == PKG  # from Insight, local-APK mode
    assert "apk" not in finished.data  # no local APK path given to this analyzer
    assert finished.data["results_dir"] == os.path.abspath(str(out_dir) + "/")
    assert isinstance(finished.data["duration_s"], float)


def test_older_insight_gets_the_privacy_fallback(monkeypatch, tmp_path, cache_root):
    seen = {}

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        seen["config_dict"] = config.config_dict
        return {"main": INSIGHT_MAIN, "security": None}, "", ""

    fake_asam = SimpleNamespace(
        Configuration=_FakeConfiguration, start_apk_static_analysis_new=start_new
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    analyzer._analysis_config.update(profile="privacy", run_tracker_analysis=False)
    pristine = json.loads(json.dumps(static_analysis._PRIVACY_PROFILE_FALLBACK))
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")

    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(tmp_path) + "/", time.time(), other_split_sha256s=[]
    )
    modules = seen["config_dict"]["modules"]
    assert modules["native_analysis"] == {"enabled": False}
    assert modules["tracker_analysis"]["enabled"] is False  # the user's choice wins
    assert modules["signature_detection"] == {"enabled": False}
    assert seen["config_dict"]["tools"]["apktool"] == {"enabled": False}
    # The fallback constant itself is never mutated by the merge.
    assert pristine == static_analysis._PRIVACY_PROFILE_FALLBACK


def test_generic_profile_adds_no_overrides(monkeypatch, tmp_path, cache_root):
    seen = {}

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        seen["config_dict"] = config.config_dict
        return {"main": INSIGHT_MAIN, "security": None}, "", ""

    fake_asam = SimpleNamespace(
        Configuration=_FakeConfiguration, start_apk_static_analysis_new=start_new
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(tmp_path) + "/", time.time(), other_split_sha256s=[]
    )
    assert "native_analysis" not in seen["config_dict"]["modules"]
    assert "tools" not in seen["config_dict"]


def test_run_without_trackers_keeps_the_previous_tracker_summary(cache_root):
    with_trackers = {
        **INSIGHT_MAIN,
        "tracker_analysis": {"detected_trackers": [{"name": "Adjust"}]},
    }
    key = ais.record_insight_result(
        ["a" * 64], with_trackers, options={"profile": "generic", "trackers": True}
    )
    ais.record_insight_result(
        ["a" * 64], INSIGHT_MAIN, options={"profile": "privacy", "trackers": False}
    )
    insight = ais.ApkCache().read_meta(key)["insight"]
    assert insight["options"]["trackers"] is False
    assert insight["trackers_from_previous_run"] is True
    assert ais.insight_trackers(insight["summary"]) == [{"name": "Adjust"}]


def test_trackers_off_without_an_analysed_run_records_null(cache_root):
    protections = {
        **INSIGHT_MAIN,
        "tracker_analysis": {
            "detected_trackers": [{"name": "Adjust"}],
            "detected_protections": [{"name": "Play Integrity"}],
        },
    }
    key = ais.record_insight_result(
        ["b" * 64], INSIGHT_MAIN, options={"profile": "privacy", "trackers": False}
    )
    insight = ais.ApkCache().read_meta(key)["insight"]
    assert insight["summary"]["tracker_analysis"] is None  # not "none found"
    assert insight["trackers_from_previous_run"] is False

    # A second trackers-off run does not adopt the first one's null.
    ais.record_insight_result(
        ["b" * 64], INSIGHT_MAIN, options={"profile": "privacy", "trackers": False}
    )
    insight = ais.ApkCache().read_meta(key)["insight"]
    assert insight["summary"]["tracker_analysis"] is None
    assert insight["trackers_from_previous_run"] is False

    # Trackers on, then off: trackers and protections are both kept, and a
    # further off run keeps them too (they still come from the analysed run).
    ais.record_insight_result(
        ["b" * 64], protections, options={"profile": "generic", "trackers": True}
    )
    for _ in range(2):
        ais.record_insight_result(
            ["b" * 64], INSIGHT_MAIN, options={"profile": "privacy", "trackers": False}
        )
        insight = ais.ApkCache().read_meta(key)["insight"]
        assert insight["trackers_from_previous_run"] is True
        assert ais.insight_trackers(insight["summary"]) == [{"name": "Adjust"}]
        assert ais.insight_protections(insight["summary"]) == [
            {"name": "Play Integrity"}
        ]


def _capturing_insight(seen, write_md=False):
    """An Insight 2.1.0 stand-in: no profile/output_dir, writes to the cwd."""

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        seen.setdefault("config_dicts", []).append(
            json.loads(json.dumps(config.config_dict))
        )
        seen.setdefault("apks", []).append(apk)
        Path("dexray_app_T.json").write_text("{}")
        Path("dexray_app_security_T.json").write_text("{}")
        if write_md:
            Path("dexray_app_security_T.md").write_text("# report")
        return (
            {"main": INSIGHT_MAIN, "security": {"x": 1}},
            "dexray_app_T.json",
            "dexray_app_security_T.json",
        )

    return SimpleNamespace(
        Configuration=_FakeConfiguration, start_apk_static_analysis_new=start_new
    )


def test_two_runs_send_the_same_config_so_insight_2_1_hits_its_cache(
    monkeypatch, tmp_path, cache_root
):
    seen = {}
    analyzer = _analyzer(monkeypatch, tmp_path, _capturing_insight(seen))
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    out = tmp_path / "out"
    out.mkdir()
    for _ in range(2):
        assert analyzer._run_dexray_analysis(
            str(apk), "app", str(out) + "/", time.time(), other_split_sha256s=[]
        )
    first, second = seen["config_dicts"]
    # Insight 2.1.0 hashes the whole config: identical dicts give identical keys.
    assert first == second
    assert seen["apks"][0] != seen["apks"][1]  # yet each run has its own folder
    assert first["temporal_analysis"]["base_directory"] == str(
        tmp_path / "insight-work"
    )


def test_fallback_moves_the_markdown_report_too(monkeypatch, tmp_path, cache_root):
    analyzer = _analyzer(monkeypatch, tmp_path, _capturing_insight({}, write_md=True))
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    out = tmp_path / "out"
    out.mkdir()
    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(out) + "/", time.time(), other_split_sha256s=[]
    )
    assert sorted(p.name for p in out.iterdir()) == [
        "dexray_app_T.json",
        "dexray_app_security_T.json",
        "dexray_app_security_T.md",
    ]
    assert list(tmp_path.glob("dexray_*")) == []


def test_stale_run_folders_are_removed_at_the_next_start(tmp_path, monkeypatch):
    root = tmp_path / "insight-work"
    old = root / "run-old"
    fresh = root / "run-fresh"
    old.mkdir(parents=True)
    fresh.mkdir()
    long_ago = time.time() - 2 * 24 * 3600
    os.utime(old, (long_ago, long_ago))
    monkeypatch.setattr(static_analysis, "insight_work_root", lambda: root)

    run_dir = static_analysis.StaticAnalysis._new_run_dir()

    assert not old.exists()
    assert fresh.exists()
    assert run_dir.parent == root


def _guard_case(monkeypatch, tmp_path, inside, *, new_insight=False):
    """Run _preserved_root_logging around a 2.1.0-style swap; return (root, host).

    Inside the guard: Insight's swap (drop root FileHandlers, add a debug log
    below the work root) and whatever ``inside(root, host)`` does.
    """
    import logging

    monkeypatch.setattr(
        static_analysis, "_insight_keeps_host_logging", lambda: new_insight
    )
    work = tmp_path / "insight-work"
    (work / "dexray_app_T" / "logs").mkdir(parents=True)
    root = logging.getLogger()
    host = logging.FileHandler(tmp_path / "session.log")
    root.addHandler(host)
    with static_analysis._preserved_root_logging(work):
        inside(root, host)
    return root, host, work


def _insight_swap(root, work):
    import logging

    for handler in [h for h in root.handlers if isinstance(h, logging.FileHandler)]:
        root.removeHandler(handler)
    root.addHandler(logging.FileHandler(work / "dexray_app_T" / "logs" / "debug.log"))


def _file_handlers(root):
    import logging

    return [h for h in root.handlers if isinstance(h, logging.FileHandler)]


def _cleanup(root, *handlers):
    for handler in handlers:
        root.removeHandler(handler)
        handler.close()


def test_insight_2_1_log_swap_is_undone(monkeypatch, tmp_path):
    work = tmp_path / "insight-work"
    root, host, work = _guard_case(
        monkeypatch, tmp_path, lambda root, host: _insight_swap(root, work)
    )
    try:
        handlers = _file_handlers(root)
        assert host in handlers
        assert not any(str(work) in h.baseFilename for h in handlers)
    finally:
        _cleanup(root, host)


def test_a_session_log_swap_during_the_run_is_kept(monkeypatch, tmp_path):
    import logging

    new_session = logging.FileHandler(tmp_path / "next-session.log")

    def swap(root, host):
        root.removeHandler(host)  # Sandroid's own session switch, not Insight
        root.addHandler(new_session)
        root.setLevel(logging.WARNING)

    level = logging.getLogger().level
    root, host, _work = _guard_case(monkeypatch, tmp_path, swap)
    try:
        assert new_session in root.handlers
        assert host not in root.handlers
        assert root.level == logging.WARNING  # the level is never reset
    finally:
        _cleanup(root, new_session, host)
        root.setLevel(level)


def test_a_newer_insight_is_left_alone(monkeypatch, tmp_path):
    work = tmp_path / "insight-work"
    root, host, work = _guard_case(
        monkeypatch,
        tmp_path,
        lambda root, host: _insight_swap(root, work),
        new_insight=True,
    )
    added = [h for h in _file_handlers(root) if str(work) in h.baseFilename]
    try:
        assert added  # untouched: Insight >= 2.2 never swaps host handlers
        assert host not in root.handlers
    finally:
        _cleanup(root, host, *added)


def _state_events(monkeypatch):
    events = []
    monkeypatch.setattr(
        static_analysis.TaskOutput, "publish", lambda self: events.append(self)
    )
    return events


def test_failed_run_publishes_a_short_failed_state(monkeypatch, tmp_path, cache_root):
    events = _state_events(monkeypatch)

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        raise RuntimeError("apktool exploded\nlong traceback line")

    fake_asam = SimpleNamespace(
        Configuration=_FakeConfiguration, start_apk_static_analysis_new=start_new
    )
    monkeypatch.setattr(static_analysis, "asam", fake_asam)
    monkeypatch.setattr(
        static_analysis, "insight_work_root", lambda: tmp_path / "insight-work"
    )
    apk = tmp_path / "Some App.apk"
    apk.write_bytes(b"apk-bytes")
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path) + "/")
    analyzer = static_analysis.StaticAnalysis(apk_path=str(apk), adb=SimpleNamespace())

    assert analyzer.gather(interactive=False) is False

    states = [e.data["state"] for e in events]
    assert states == ["started", "failed"]
    failed = events[-1]
    assert failed.data["error"] == "apktool exploded"
    assert failed.data["apk"] == "Some App.apk"
    assert failed.data["package"] is None  # unknown: Insight never answered
    assert failed.data["profile"] == "generic"
    assert list((tmp_path / "insight-work").iterdir()) == []


def test_dialog_cancel_and_stop_publish_cancelled(monkeypatch, tmp_path, cache_root):
    events = _state_events(monkeypatch)
    fake_asam = SimpleNamespace(
        Configuration=_FakeConfiguration,
        start_apk_static_analysis_new=lambda *a, **k: (_ for _ in ()).throw(
            KeyboardInterrupt()
        ),
    )
    monkeypatch.setattr(static_analysis, "asam", fake_asam)
    monkeypatch.setattr(
        static_analysis, "insight_work_root", lambda: tmp_path / "insight-work"
    )
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    monkeypatch.setenv("RESULTS_PATH", str(tmp_path) + "/")
    analyzer = static_analysis.StaticAnalysis(apk_path=str(apk), adb=SimpleNamespace())

    monkeypatch.setattr(analyzer, "_interactive_configuration", lambda: None)
    assert analyzer.gather(interactive=True) is False
    assert [e.data["state"] for e in events] == ["cancelled"]

    events.clear()
    with pytest.raises(KeyboardInterrupt):
        analyzer.gather(interactive=False)
    assert [e.data["state"] for e in events] == ["started", "cancelled"]
    assert list((tmp_path / "insight-work").iterdir()) == []


def test_privacy_fallback_equals_insights_privacy_profile():
    profiles = pytest.importorskip("dexray_insight.core.profiles")
    expected = profiles.get_profile_overrides("privacy")
    assert expected == static_analysis._PRIVACY_PROFILE_FALLBACK


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
            # Pulled into the run's own work folder, not the results folder.
            target = Path(shlex.split(command)[-1])
            assert target.parent.parent == tmp_path / "insight-work"
            target.write_bytes(b"base")
            return "1 file pulled", ""
        if "sha256sum" in command:
            return SHA_OUT, ""
        return "", ""

    monkeypatch.setattr(analyzer, "_send_adb_command", send)
    monkeypatch.setattr(
        "sandroid.services.get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: PKG),
    )
    monkeypatch.setattr(
        analyzer,
        "_get_toolbox",
        lambda: SimpleNamespace(mark_tool_used=lambda *a, **k: None),
    )

    assert analyzer._analyze_device_apk(time.time())
    pull = next(c for c in commands if c.startswith("pull "))
    assert "/base.apk" in pull
    assert "split_config" not in pull
    # Only a config split besides base: it is not hashed and not in the key.
    assert not any("sha256sum" in c for c in commands)
    key = ais.hashlib.sha256(b"base").hexdigest()
    assert ais.ApkCache().read_meta(key)["insight"]["cache"] is None


# ---------------------------------------------------------------------------
# Facade never-raise contract vs. the AI tools' original error behaviour
# ---------------------------------------------------------------------------


def _raise(*_a, **_k):
    raise RuntimeError("adb exploded")


def test_facade_details_pid_installed_never_raise(monkeypatch):
    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(_raise))
    monkeypatch.setattr(Adb, "get_pid_for_package_name", staticmethod(_raise))
    monkeypatch.setattr(Adb, "get_installed_packages", staticmethod(_raise))
    service = ais.AppInfoService("emulator-5554")

    for fact in (service.details(PKG), service.pid(PKG), service.installed()):
        assert fact.ok is False
        assert "adb exploded" in fact.reason
    assert service.details("bad;pkg").reason.startswith("invalid")


def test_facade_details_reports_missing_package(fake_adb):
    fake_adb({"dumpsys package": ""})
    fact = ais.AppInfoService().details(PKG)
    assert fact.ok is False
    assert "package not found" in fact.reason

    fake_adb({"dumpsys package": DUMPSYS_PACKAGE_API30})
    fact = ais.AppInfoService().details(PKG)
    assert fact.ok
    assert fact.value["uid"] == 10123


def test_ai_tools_keep_original_error_behaviour(monkeypatch):
    from sandroid.ai.tools import app_query

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(_raise))
    with pytest.raises(RuntimeError, match="adb exploded"):
        app_query.get_package_details(PKG)
    with pytest.raises(RuntimeError, match="adb exploded"):
        app_query.list_exported_components(PKG)


# ---------------------------------------------------------------------------
# Insight summary: no host paths; trackers and protections kept
# ---------------------------------------------------------------------------

INSIGHT_WITH_PATHS = {
    "apk_overview": {
        "general_info": {"package_name": PKG},
        "native_libs": ["lib/arm64-v8a/libflutter.so"],
    },
    "apkid_analysis": {
        "files": [
            {
                "filename": "/Users/someone/work/run/app.apk!classes2.dex",
                "matches": {"anti_vm": ["Build.MODEL check"]},
            },
            {"filename": "/Users/someone/work/run/app.apk", "matches": {}},
        ],
        "raw_output": "x",
    },
    "tracker_analysis": {
        "detected_trackers": [
            {
                "name": "Google AdMob",
                "category": "Advertisement",
                "version": "22.1",
                "website": "https://admob.google.com",
                "network_signature": "googleads.g.doubleclick.net",
                "locations": ["/home/someone/apktool/smali/com/google/Ads.smali"],
                "code_signature": "com.google.android.gms.ads",
            }
        ],
        "detected_protections": [
            {
                "id": "rootbeer",
                "name": "RootBeer",
                "defeats": ["root"],
                "confidence": "high",
                "evidence": "entry_point",
                "matched_libs": ["/private/tmp/x/lib/arm64-v8a/libtoolChecker.so"],
            }
        ],
    },
}


def test_insight_summary_scrubs_host_paths_and_keeps_trackers(cache_root):
    key = ais.record_insight_result([H1], INSIGHT_WITH_PATHS)
    meta = ais.ApkCache().read_meta(key)
    text = json.dumps(meta)
    for leak in ("/Users/", "/home/", "/private/"):
        assert leak not in text
    summary = meta["insight"]["summary"]
    names = [f["filename"] for f in summary["apkid_analysis"]["files"]]
    assert names == ["classes2.dex", "app.apk"]
    (tracker,) = summary["tracker_analysis"]["detected_trackers"]
    assert tracker["name"] == "Google AdMob"
    assert tracker["website"] == "https://admob.google.com"  # URLs untouched
    assert "locations" not in tracker
    (protection,) = summary["tracker_analysis"]["detected_protections"]
    assert protection["evidence"] == "entry_point"
    assert protection["confidence"] == "high"
    assert protection["matched_libs"] == ["libtoolChecker.so"]
    assert summary["apk_overview"]["native_libs"] == ["lib/arm64-v8a/libflutter.so"]


def test_scrub_paths_generic():
    scrubbed = ais.scrub_paths(
        {
            "a": "error reading /home/u/run/f.json line 3",
            "b": ["C:\\Users\\u\\app.apk", "lib/x86/libc++.so", "com.foo.Bar"],
            "c": 5,
        }
    )
    assert scrubbed == {
        "a": "error reading f.json line 3",
        "b": ["app.apk", "lib/x86/libc++.so", "com.foo.Bar"],
        "c": 5,
    }


def test_static_overview_exposes_trackers_and_protections(fake_adb, cache_root):
    fake_adb({"pm path": PM_PATH, "sha256sum": SHA_OUT})
    ais.ApkCache().write_entry(
        H1,
        overview={
            "schema": ais.OVERVIEW_SCHEMA,
            "androguard_version": ais._androguard_version(),
            "requested_permissions": [],
        },
    )
    ais.record_insight_result([H1], INSIGHT_WITH_PATHS)

    result = ais.get_static_overview(PKG)

    assert result.from_cache
    assert [t["name"] for t in result.trackers] == ["Google AdMob"]
    assert [p["name"] for p in result.protections] == ["RootBeer"]
    assert "trackers" in result.to_dict()
    assert ais.insight_trackers("garbage") == []


# ---------------------------------------------------------------------------
# Insight offline configuration
# ---------------------------------------------------------------------------


class _Insight2Configuration:
    DEFAULT_CONFIG = {
        "caching": {"enabled": True},
        "modules": {
            "tracker_analysis": {
                "fetch_exodus_trackers": True,
                "exodus_offline": False,
            },
            "library_detection": {"version_analysis": {"enabled": True}},
        },
    }

    def __init__(self, config_dict=None):
        self.config_dict = config_dict


class _Insight1Configuration:
    DEFAULT_CONFIG = {
        "modules": {"tracker_analysis": {"fetch_exodus_trackers": True}},
    }

    def __init__(self, config_dict=None):
        self.config_dict = config_dict


def _offline_run(monkeypatch, tmp_path, configuration, **analysis_config):
    seen = {}

    def start_new(apk, config, print_results_to_terminal=False, verbose=False):
        seen["config"] = config.config_dict
        return {"main": INSIGHT_MAIN, "security": None}, "", ""

    fake_asam = SimpleNamespace(
        Configuration=configuration,
        start_apk_static_analysis_new=start_new,
        start_apk_static_analysis=lambda **k: pytest.fail("legacy path used"),
    )
    analyzer = _analyzer(monkeypatch, tmp_path, fake_asam)
    analyzer._analysis_config.update(analysis_config)
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"apk-bytes")
    assert analyzer._run_dexray_analysis(
        str(apk), "app", str(tmp_path) + "/", time.time(), other_split_sha256s=[]
    )
    return seen["config"]


def test_insight2_offline_config(monkeypatch, tmp_path, cache_root, caplog):
    caplog.set_level("INFO", logger="sandroid.analysis.static_analysis")
    config = _offline_run(monkeypatch, tmp_path, _Insight2Configuration)

    modules = config["modules"]
    assert modules["tracker_analysis"] == {"exodus_offline": True}
    libs = modules["library_detection"]
    assert libs["apktool_detection"]["auto_update_definitions"] is False
    assert libs["version_analysis"]["enabled"] is False
    assert config["security"]["cve_scanning"]["enabled"] is False
    assert config["security"]["enable_owasp_assessment"] is True  # kept
    assert config["modules"]["signature_detection"]["enabled"] is False
    assert "caching" in config
    offline_lines = [r for r in caplog.records if "runs offline" in r.getMessage()]
    assert len(offline_lines) == 1


def test_insight1_offline_uses_fetch_flag_and_no_cache(
    monkeypatch, tmp_path, cache_root
):
    config = _offline_run(monkeypatch, tmp_path, _Insight1Configuration)
    assert config["modules"]["tracker_analysis"] == {"fetch_exodus_trackers": False}
    assert "caching" not in config  # 1.0.0.1 has no analysis cache


def test_insight_online_when_configured(monkeypatch, tmp_path, cache_root):
    config = _offline_run(
        monkeypatch, tmp_path, _Insight2Configuration, insight_offline=False
    )
    assert "tracker_analysis" not in config["modules"]
    assert "cve_scanning" not in config["security"]


def test_insight_offline_default_comes_from_config(monkeypatch, tmp_path):
    from sandroid.config.schema import AnalysisConfig

    assert AnalysisConfig().insight_offline is True
    analyzer = static_analysis.StaticAnalysis(adb=SimpleNamespace())
    monkeypatch.setattr(
        static_analysis,
        "get_config",
        lambda: SimpleNamespace(analysis=SimpleNamespace(insight_offline=False)),
    )
    assert analyzer._insight_offline() is False


# ---------------------------------------------------------------------------
# Real API 35 arm64 AVD fixtures (synthetic device data, trimmed)
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "app_info"
REAL_APPOPS_PACKAGES = [
    "com.google.android.gms",
    "com.google.android.dialer",
    "com.android.settings",
    "com.google.android.apps.nexuslauncher",
]


def _fx(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_real_gms_running_ops_from_dumpsys():
    dumpsys = {
        o.op: o
        for o in ais.parse_appops(_fx("com.google.android.gms.dumpsys_appops.dump"))
    }
    cmd = {
        o.op: o
        for o in ais.parse_appops(_fx("com.google.android.gms.cmd_appops_get.dump"))
    }
    running = {op for op, o in dumpsys.items() if o.running}
    assert running == {
        "MONITOR_LOCATION",
        "ACTIVITY_RECOGNITION",
        "ACTIVITY_RECOGNITION_SOURCE",
    }
    assert running == {op for op, o in cmd.items() if o.running}
    monitor = dumpsys["MONITOR_LOCATION"]
    assert monitor.package_mode == "allow"
    assert monitor.foreground is True


@pytest.mark.parametrize("package", REAL_APPOPS_PACKAGES)
def test_real_cmd_appops_scopes_match_dumpsys(package):
    cmd = {o.op: o for o in ais.parse_appops(_fx(f"{package}.cmd_appops_get.dump"))}
    dumpsys = {o.op: o for o in ais.parse_appops(_fx(f"{package}.dumpsys_appops.dump"))}
    assert set(cmd) == set(dumpsys)
    for op, entry in cmd.items():
        truth = dumpsys[op]
        assert (entry.uid_mode, entry.package_mode, entry.mode) == (
            truth.uid_mode,
            truth.package_mode,
            truth.mode,
        ), op


def test_real_gms_package_line_after_uid_block_is_package_scope():
    # Uid block ends with READ_WRITE_HEALTH_DATA (op 126); the next line
    # "COARSE_LOCATION: allow" has no time fields but op code 0 -> package.
    ops = {
        o.op: o
        for o in ais.parse_appops(_fx("com.google.android.gms.cmd_appops_get.dump"))
    }
    assert ops["READ_WRITE_HEALTH_DATA"].uid_mode == "ignore"
    assert ops["COARSE_LOCATION"].uid_mode is None
    assert ops["COARSE_LOCATION"].package_mode == "allow"
    assert ops["CAMERA"].uid_mode == "foreground"


def _dumpsys_op_sequences(text: str) -> list[list[str]]:
    seqs: list[list[str]] = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"(Package \S+|Uid \S+):$", stripped):
            current = []
            seqs.append(current)
            continue
        match = re.match(r"^([A-Z][A-Z0-9_]+)(?: \(|: mode=)", stripped)
        indent = len(line) - len(line.lstrip())
        if match and current is not None and indent == 6:
            current.append(match.group(1))
    return seqs


@pytest.mark.parametrize("package", REAL_APPOPS_PACKAGES)
def test_op_code_table_matches_real_dump_order(package):
    seqs = _dumpsys_op_sequences(_fx(f"{package}.dumpsys_appops.dump"))
    assert seqs
    for seq in seqs:
        assert all(op in ais._OP_CODE for op in seq), seq
        codes = [ais._OP_CODE[op] for op in seq]
        assert codes == sorted(codes)
        assert len(set(codes)) == len(codes)


def test_real_shared_uid_settings_grants():
    state = ais.parse_permission_state(
        _fx("com.android.settings.dumpsys_package.dump"), "com.android.settings"
    )
    by_name = {p.name: p for p in state.permissions}
    assert state.ok
    assert state.shared_user == "android.uid.system"
    for name in (
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
    ):
        grant = by_name[name]
        assert (grant.kind, grant.granted) == ("runtime", True), name
        assert "SYSTEM_FIXED" in grant.flags
        # RESTRICTION_*_EXEMPT flags mean exempt, not restricted.
        assert grant.restricted is False, name
        assert grant.protection == "dangerous"
    assert by_name["android.permission.WRITE_SETTINGS"].kind == "install"
    assert by_name["android.permission.WRITE_SETTINGS"].granted is True


def test_real_dialer_hash_permission_and_revoked_compat():
    text = _fx("com.google.android.dialer.dumpsys_package.dump")
    state = ais.parse_permission_state(text, "com.google.android.dialer")
    by_name = {p.name: p for p in state.permissions}
    tycho = "com.google.android.apps.tycho#com.google.android.ims.providers.ACCESS_DATA"
    assert by_name[tycho].requested is True
    audio = by_name["android.permission.RECORD_AUDIO"]
    assert audio.granted is True
    assert audio.revoked is True
    assert audio.effective_granted is False
    assert "REVOKED_COMPAT" in audio.revoked_reason
    # The real AppOps agree: RECORD_AUDIO is ignored at uid level.
    appops = ais.AppOpsState(
        package="com.google.android.dialer",
        ops=ais.parse_appops(_fx("com.google.android.dialer.cmd_appops_get.dump")),
    )
    ais.apply_appops_revocations(state, appops)
    assert audio.revoked_reason.startswith("REVOKED_COMPAT")  # first reason kept


def test_apply_appops_revocations_uid_ignore():
    state = ais.PermissionState(
        package=PKG,
        permissions=[
            ais.PermissionGrant(
                "android.permission.CAMERA", kind="runtime", granted=True
            ),
            ais.PermissionGrant(
                "android.permission.ACCESS_FINE_LOCATION", kind="runtime", granted=True
            ),
        ],
    )
    ops = ais.parse_appops("Uid mode: FINE_LOCATION: foreground\nCAMERA: ignore\n")
    ais.apply_appops_revocations(state, ais.AppOpsState(package=PKG, ops=ops))
    camera, fine = state.permissions
    assert camera.revoked is True
    assert camera.revoked_reason == "AppOps CAMERA uid mode ignore"
    assert fine.revoked is False  # foreground = while-in-use, not revoked
    ais.apply_appops_revocations(state, None)  # tolerated


def _real_footprint_output(package: str) -> str:
    du = {}
    for line in _fx("du_incl_user_de.dump").splitlines():
        match = re.match(r"^(\d+)\t(\S+)$", line)
        if match:
            du[match.group(2)] = line
    sep = "\n@@SANDROID_SEP@@\n"
    return sep.join(
        [
            du[f"/data/data/{package}"],
            du[f"/data/user_de/0/{package}"],
            f"du: /sdcard/Android/data/{package}: No such file or directory",
            f"ls: /data/data/{package}/shared_prefs: No such file or directory",
            f"ls: /data/data/{package}/databases: No such file or directory",
            "development_settings.xml\nsettings_preferences.xml",
            f"ls: /data/user_de/0/{package}/databases: No such file or directory",
        ]
    )


def test_real_settings_footprint_counts_de_storage(fake_adb):
    settings = "com.android.settings"
    data_dir_line = next(
        line
        for line in _fx("com.android.settings.dumpsys_package.dump").splitlines()
        if "dataDir=" in line
    )
    fake = fake_adb(
        {
            "dataDir": data_dir_line,
            "du -sk": _real_footprint_output(settings),
            "shell id": "uid=0(root)",
        }
    )
    result = ais.get_data_footprint(settings)

    assert result.data_dir == "/data/user_de/0/com.android.settings"
    assert (result.private_kb, result.de_kb) == (24, 1048)
    assert result.private_total_kb == 1072
    assert result.external_reason == "absent"
    assert result.shared_prefs_count == 2  # found in DE, not CE
    assert result.databases_count == 0
    script = next(c for c, _s in fake.calls if "du -sk" in c)
    assert "/data/user_de/0/com.android.settings" in script


def test_static_analysis_uses_a_selected_spotlight(monkeypatch, tmp_path):
    """An app picked with ⇧C but not started (spawn mode) is analysed.

    A real service in spawn mode: the attach-only legacy getter returned
    None there and `pm path` crashed with "can only concatenate str".
    """
    from sandroid import services
    from sandroid.services.spotlight_service import SpotlightService

    spotlight = SpotlightService()
    spotlight.set_app("org.mozilla.firefox")
    monkeypatch.setattr(services, "get_spotlight_service", lambda: spotlight)
    analyzer = static_analysis.StaticAnalysis(adb=SimpleNamespace())
    seen = []

    def fake_adb(cmd):
        seen.append(cmd)
        return "", "error: stop here"

    monkeypatch.setattr(analyzer, "_send_adb_command", fake_adb)
    monkeypatch.chdir(tmp_path)
    analyzer._analyze_device_apk(time.time())
    assert seen
    assert seen[0] == "shell pm path org.mozilla.firefox"
    assert analyzer.last_analysed_app == "org.mozilla.firefox"


def test_static_analysis_without_spotlight_fails_cleanly(monkeypatch, tmp_path):
    from sandroid import services

    fake_service = SimpleNamespace(get_effective_package=lambda: None)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake_service)
    analyzer = static_analysis.StaticAnalysis(adb=SimpleNamespace())
    monkeypatch.setattr(
        analyzer, "_send_adb_command", lambda c: pytest.fail("adb called")
    )
    monkeypatch.chdir(tmp_path)
    assert analyzer._analyze_device_apk(time.time()) is False
    assert analyzer.last_results == {"error": "no spotlight app selected"}


def test_permission_counts_keep_a_real_zero():
    from types import SimpleNamespace

    from sandroid.services.app_info_service import permission_counts

    read = SimpleNamespace(ok=True, permissions=[], api_level=35)
    assert permission_counts(read)[0] == 0  # read; the app requests nothing
    unread = SimpleNamespace(ok=False, permissions=[], api_level=None)
    assert permission_counts(unread)[0] is None  # dumpsys not read
