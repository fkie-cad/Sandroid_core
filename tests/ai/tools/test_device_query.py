"""Unit tests for sandroid.ai.tools.device_query.

``Adb`` is imported at module level in ``device_query.py``, so tests
monkeypatch its classmethods directly on ``sandroid.core.adb.Adb`` --
wrapped in ``staticmethod(...)``, matching the existing convention in
``tests/analysis/test_spawn_retry.py``'s ``force_stop_spy`` fixture.

``get_device_settings_service`` is looked up lazily inside
``check_root_and_magisk``'s own body (see that function's docstring), so its
tests monkeypatch ``sandroid.services.get_device_settings_service`` instead --
the same convention ``tests/ai/test_context.py`` uses for sibling accessors.
"""

from types import SimpleNamespace

from sandroid import services
from sandroid.ai.tools import device_query
from sandroid.core.adb import Adb

# -- get_build_and_patch_info ---------------------------------------------------


def test_get_build_and_patch_info_maps_getprops(monkeypatch):
    values = {
        "ro.build.fingerprint": "google/sdk_gphone/generic:14/UPB2.230000/1:userdebug/dev-keys",
        "ro.build.tags": "release-keys",
        "ro.build.version.security_patch": "2026-06-01",
    }
    monkeypatch.setattr(
        Adb, "_getprop", staticmethod(lambda prop_name: values[prop_name])
    )

    assert device_query.get_build_and_patch_info() == {
        "fingerprint": values["ro.build.fingerprint"],
        "tags": values["ro.build.tags"],
        "security_patch": values["ro.build.version.security_patch"],
    }


def test_get_build_and_patch_info_handles_empty_getprop_result(monkeypatch):
    monkeypatch.setattr(Adb, "_getprop", staticmethod(lambda prop_name: None))

    assert device_query.get_build_and_patch_info() == {
        "fingerprint": None,
        "tags": None,
        "security_patch": None,
    }


def test_get_build_and_patch_info_tolerates_a_single_failing_field(monkeypatch):
    """One prop's lookup raising must not blank out the other two fields."""

    def fake_getprop(prop_name):
        if prop_name == "ro.build.tags":
            raise RuntimeError("adb hiccup")
        return f"value-for-{prop_name}"

    monkeypatch.setattr(Adb, "_getprop", staticmethod(fake_getprop))

    result = device_query.get_build_and_patch_info()

    assert result["tags"] is None
    assert result["fingerprint"] == "value-for-ro.build.fingerprint"
    assert result["security_patch"] == "value-for-ro.build.version.security_patch"


# -- check_root_and_magisk -------------------------------------------------------


def test_check_root_and_magisk_reports_both_flags(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_device_settings_service",
        lambda: SimpleNamespace(check_root_available=lambda: True),
    )
    monkeypatch.setattr(
        Adb, "_is_package_installed", staticmethod(lambda package_name: False)
    )

    assert device_query.check_root_and_magisk() == {
        "root_available": True,
        "magisk_installed": False,
    }


def test_check_root_and_magisk_reports_both_flags_inverted(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_device_settings_service",
        lambda: SimpleNamespace(check_root_available=lambda: False),
    )
    monkeypatch.setattr(
        Adb, "_is_package_installed", staticmethod(lambda package_name: True)
    )

    assert device_query.check_root_and_magisk() == {
        "root_available": False,
        "magisk_installed": True,
    }


def test_check_root_and_magisk_queries_the_magisk_package_name(monkeypatch):
    captured = {}

    def fake_is_installed(package_name):
        captured["package_name"] = package_name
        return False

    monkeypatch.setattr(
        services,
        "get_device_settings_service",
        lambda: SimpleNamespace(check_root_available=lambda: True),
    )
    monkeypatch.setattr(Adb, "_is_package_installed", staticmethod(fake_is_installed))

    device_query.check_root_and_magisk()

    assert captured["package_name"] == "com.topjohnwu.magisk"
