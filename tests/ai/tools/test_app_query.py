"""Unit tests for sandroid.ai.tools.app_query.

``Adb`` is imported at module level in ``app_query.py``
(``from sandroid.core.adb import Adb``), so tests monkeypatch its
classmethods directly on ``sandroid.core.adb.Adb`` -- wrapped in
``staticmethod(...)``, matching the existing convention in
``tests/analysis/test_spawn_retry.py``'s ``force_stop_spy`` fixture, so the
patched attribute stays callable the same way the real classmethod is
(class-level access to a plain function would otherwise leave a stray
``cls``/``self`` slot unfilled).

``resolve_package_name``'s spotlight-app fallback does its
``from sandroid.services import get_spotlight_service`` lazily inside the
function body (see ``_shared.py``'s own docstring), so tests exercising that
fallback monkeypatch ``sandroid.services.get_spotlight_service`` instead --
the same convention ``tests/ai/test_context.py`` uses for sibling accessors.
"""

from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import app_query
from sandroid.core.adb import Adb

# -- get_foreground_app -------------------------------------------------------


def test_get_foreground_app_shapes_tuple_as_dict(monkeypatch):
    monkeypatch.setattr(
        Adb,
        "get_focused_app",
        staticmethod(lambda: ("com.example.app", ".MainActivity")),
    )

    assert app_query.get_foreground_app() == {
        "package": "com.example.app",
        "activity": ".MainActivity",
    }


def test_get_foreground_app_handles_none_none(monkeypatch):
    monkeypatch.setattr(Adb, "get_focused_app", staticmethod(lambda: (None, None)))

    assert app_query.get_foreground_app() == {"package": None, "activity": None}


# -- is_package_installed ------------------------------------------------------


def test_is_package_installed_wraps_bool(monkeypatch):
    monkeypatch.setattr(
        Adb, "_is_package_installed", staticmethod(lambda package_name: True)
    )

    assert app_query.is_package_installed("com.example.app") == {"installed": True}


# -- list_installed_packages ----------------------------------------------------


def test_list_installed_packages_defaults_to_user_only(monkeypatch):
    captured = {}

    def fake_get_installed_packages(user_only=False):
        captured["user_only"] = user_only
        return [
            {
                "package_name": "com.example.app",
                "install_date": None,
                "is_user_app": True,
            }
        ]

    monkeypatch.setattr(
        Adb, "get_installed_packages", staticmethod(fake_get_installed_packages)
    )

    result = app_query.list_installed_packages()

    assert captured["user_only"] is True
    assert result == {
        "packages": [
            {
                "package_name": "com.example.app",
                "install_date": None,
                "is_user_app": True,
            }
        ],
        "count": 1,
    }


def test_list_installed_packages_include_system_flips_user_only(monkeypatch):
    captured = {}

    def fake_get_installed_packages(user_only=False):
        captured["user_only"] = user_only
        return []

    monkeypatch.setattr(
        Adb, "get_installed_packages", staticmethod(fake_get_installed_packages)
    )

    app_query.list_installed_packages(include_system=True)

    assert captured["user_only"] is False


def test_list_installed_packages_coerces_stringified_booleans(monkeypatch):
    """A model that emits a JSON string instead of a real JSON boolean for
    this ``"type": "boolean"`` parameter is a real, observed failure mode
    (arguments pass through `json.loads` with no schema validation -- see
    `ToolRegistry.dispatch`). Without coercion, `not "false"` is `False` in
    Python (any non-empty string is truthy), silently including system
    packages when the caller asked to exclude them.
    """
    captured = {}

    def fake_get_installed_packages(user_only=False):
        captured["user_only"] = user_only
        return []

    monkeypatch.setattr(
        Adb, "get_installed_packages", staticmethod(fake_get_installed_packages)
    )

    app_query.list_installed_packages(include_system="false")
    assert captured["user_only"] is True

    app_query.list_installed_packages(include_system="true")
    assert captured["user_only"] is False


# -- get_package_pid ------------------------------------------------------------


def test_get_package_pid_forces_use_frida_fallback_false(monkeypatch):
    captured = {}

    def fake_get_pid(package_name, use_frida_fallback=True, quiet=False):
        captured["use_frida_fallback"] = use_frida_fallback
        return 1234

    monkeypatch.setattr(Adb, "get_pid_for_package_name", staticmethod(fake_get_pid))

    result = app_query.get_package_pid("com.example.app")

    assert captured["use_frida_fallback"] is False
    assert result == {"package_name": "com.example.app", "pid": 1234}


def test_get_package_pid_defaults_to_spotlight_package_when_omitted(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: "com.spotlight.app"),
    )
    monkeypatch.setattr(
        Adb,
        "get_pid_for_package_name",
        staticmethod(lambda package_name, use_frida_fallback=True, quiet=False: 42),
    )

    assert app_query.get_package_pid() == {
        "package_name": "com.spotlight.app",
        "pid": 42,
    }


def test_get_package_pid_raises_when_omitted_and_no_spotlight(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: None),
    )

    with pytest.raises(ToolExecutionError):
        app_query.get_package_pid()


# -- get_package_details --------------------------------------------------------

_PACKAGE_DETAILS_FIXTURE = """
Packages:
  Package [com.example.app] (abc123):
    userId=10123
    versionCode=42 minSdk=24 targetSdk=34
    versionName=1.2.3
    dataDir=/data/user/0/com.example.app
    firstInstallTime=2026-01-01 00:00:00
    signatures=PackageSignatures{deadbeef version:2}
    installerPackageName=com.android.vending
    requested permissions:
      android.permission.INTERNET
"""


def test_get_package_details_merges_parser_output_with_package_name(monkeypatch):
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(lambda command: (_PACKAGE_DETAILS_FIXTURE, "")),
    )

    result = app_query.get_package_details("com.example.app")

    assert result["package_name"] == "com.example.app"
    assert result["uid"] == 10123
    assert result["version_name"] == "1.2.3"
    assert result["install_source"] == "com.android.vending"
    assert result["requested_permissions"] == ["android.permission.INTERNET"]


def test_get_package_details_raises_clear_error_when_no_package_and_no_spotlight(
    monkeypatch,
):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: None),
    )

    with pytest.raises(ToolExecutionError):
        app_query.get_package_details()


# -- list_exported_components ----------------------------------------------------
#
# Bug-fix context: this tool used to feed raw `dumpsys package <pkg>` text
# (via `Adb.send_adb_command`) straight into `parse_component_info`. Three
# independent verification passes confirmed real `dumpsys package` output
# has no exported/permission/intent-filter data at all -- so the tool now
# pulls the app's real APK(s) (`pm path` + `pull`) and decodes the manifest
# via `androguard` instead (see `_pull_and_parse_manifests`). These tests
# monkeypatch `_pull_and_parse_manifests` directly -- the real ADB+androguard
# round trip is exercised empirically against a live emulator instead (not
# practical to run in a unit test); `parse_component_info`'s own manifest
# parsing is covered against real captured manifest fixtures in
# `tests/services/test_component_info_parser.py`.


def _component_info(
    *,
    activities=(),
    services=(),
    receivers=(),
    providers=(),
):
    return {
        "components": {
            "activities": list(activities),
            "services": list(services),
            "receivers": list(receivers),
            "providers": list(providers),
        }
    }


def test_list_exported_components_shapes_and_counts_merged_output(monkeypatch):
    manifest_info = _component_info(
        activities=[
            {
                "name": "com.example.app.MainActivity",
                "exported": True,
                "permission": None,
                "intent_filters": [],
            }
        ],
        services=[
            {
                "name": "com.example.app.BackgroundService",
                "exported": False,
                "permission": "com.example.app.permission.BIND",
                "intent_filters": [],
            }
        ],
        receivers=[
            {
                "name": "com.example.app.BootReceiver",
                "exported": True,
                "permission": None,
                "intent_filters": [],
            }
        ],
        providers=[
            {
                "name": "com.example.app.PublicProvider",
                "exported": True,
                "read_permission": None,
                "write_permission": None,
                "authorities": ["com.example.app.provider"],
            }
        ],
    )
    monkeypatch.setattr(
        app_query, "_pull_and_parse_manifests", lambda pkg: [manifest_info]
    )

    result = app_query.list_exported_components("com.example.app")

    assert result["package_name"] == "com.example.app"
    components = result["components"]
    assert components["activities"] == manifest_info["components"]["activities"]
    assert components["services"][0]["exported"] is False
    assert components["services"][0]["permission"] == (
        "com.example.app.permission.BIND"
    )
    assert components["receivers"][0]["exported"] is True
    assert components["providers"] == manifest_info["components"]["providers"]
    # Unguarded + exported: MainActivity (no permission), BootReceiver (no
    # permission), PublicProvider (no read/write permission). Not counted:
    # BackgroundService is guarded by a permission *and* not exported either
    # way.
    assert result["exported_without_permission_count"] == 3


def test_list_exported_components_merges_multiple_splits(monkeypatch):
    base = _component_info(
        activities=[
            {
                "name": "com.example.app.MainActivity",
                "exported": True,
                "permission": None,
                "intent_filters": [],
            }
        ]
    )
    split = _component_info(
        activities=[
            {
                "name": "com.example.app.feature.FeatureActivity",
                "exported": True,
                "permission": None,
                "intent_filters": [],
            }
        ]
    )
    monkeypatch.setattr(
        app_query, "_pull_and_parse_manifests", lambda pkg: [base, split]
    )

    result = app_query.list_exported_components("com.example.app")

    names = {a["name"] for a in result["components"]["activities"]}
    assert names == {
        "com.example.app.MainActivity",
        "com.example.app.feature.FeatureActivity",
    }


def test_list_exported_components_defaults_to_spotlight_package_when_omitted(
    monkeypatch,
):
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: "com.spotlight.app"),
    )
    monkeypatch.setattr(app_query, "_pull_and_parse_manifests", lambda pkg: [])

    result = app_query.list_exported_components()

    assert result["package_name"] == "com.spotlight.app"
    assert result["exported_without_permission_count"] == 0


def test_list_exported_components_empty_when_package_not_installed(monkeypatch):
    monkeypatch.setattr(
        Adb, "send_adb_command", staticmethod(lambda command: ("", "not installed"))
    )

    result = app_query.list_exported_components("com.missing.app")

    assert result["components"] == {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    assert result["exported_without_permission_count"] == 0


def test_list_exported_components_raises_when_androguard_unavailable(monkeypatch):
    monkeypatch.setattr(app_query, "APK", None)
    monkeypatch.setattr(
        Adb,
        "send_adb_command",
        staticmethod(
            lambda command: ("package:/data/app/com.example.app/base.apk", "")
        ),
    )

    with pytest.raises(ToolExecutionError):
        app_query.list_exported_components("com.example.app")


# -- _parse_pm_path_output ----------------------------------------------------


def test_parse_pm_path_output_single_apk():
    stdout = "package:/data/app/~~abc==/com.example.app-xyz==/base.apk\n"

    assert app_query._parse_pm_path_output(stdout) == [
        "/data/app/~~abc==/com.example.app-xyz==/base.apk"
    ]


def test_parse_pm_path_output_multiple_splits():
    # Real shape verified on a live emulator (Microsoft Edge): base.apk plus
    # several split_*.apk lines.
    stdout = (
        "package:/data/app/~~abc==/com.example.app-xyz==/base.apk\n"
        "package:/data/app/~~abc==/com.example.app-xyz==/split_config.arm64_v8a.apk\n"
        "package:/data/app/~~abc==/com.example.app-xyz==/split_config.en.apk\n"
    )

    assert app_query._parse_pm_path_output(stdout) == [
        "/data/app/~~abc==/com.example.app-xyz==/base.apk",
        "/data/app/~~abc==/com.example.app-xyz==/split_config.arm64_v8a.apk",
        "/data/app/~~abc==/com.example.app-xyz==/split_config.en.apk",
    ]


def test_parse_pm_path_output_empty_when_not_installed():
    assert app_query._parse_pm_path_output("") == []
