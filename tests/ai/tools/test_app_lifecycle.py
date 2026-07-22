"""Unit tests for sandroid.ai.tools.app_lifecycle.

``Adb`` is imported at module level, so its classmethods are monkeypatched
directly on ``sandroid.core.adb.Adb`` (matching
``tests/ai/tools/test_device_query.py``). ``resolve_confined_host_path`` is
imported by name into ``app_lifecycle``'s own namespace (``from
sandroid.ai.tools._host_paths import resolve_confined_host_path``), so tests
monkeypatch ``app_lifecycle.resolve_confined_host_path`` directly rather than
patching ``_host_paths.resolve_confined_host_path`` (which would not affect
the already-bound name in ``app_lifecycle``) -- confinement behavior itself
is covered by ``tests/ai/tools/test_host_paths.py``.
"""

from pathlib import Path

import pytest

from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import app_lifecycle
from sandroid.core.adb import Adb
from sandroid.core.exceptions import APKInstallError

# -- install_apk --------------------------------------------------------------------


def test_install_apk_success_resolves_host_path_and_quotes_it(monkeypatch):
    resolved = Path("/host/ai_share/app.apk")
    monkeypatch.setattr(app_lifecycle, "resolve_confined_host_path", lambda p: resolved)

    captured = {}

    def fake_install_apk(apk_path):
        captured["apk_path"] = apk_path
        return "com.example.app"

    monkeypatch.setattr(Adb, "install_apk", staticmethod(fake_install_apk))

    result = app_lifecycle.install_apk("app.apk")

    assert result == {"installed": True, "package_name": "com.example.app"}
    assert captured["apk_path"] == str(resolved)


def test_install_apk_rejects_path_with_shell_metacharacters(monkeypatch):
    """Regression (review-caught bug): apk_path must NOT be shlex.quote()-d --
    Adb.install_apk internally also passes it as a literal argv element to a
    non-shell subprocess.run([...]) call (aapt), so quote characters baked
    into the string would corrupt that lookup. Instead, a resolved path
    containing a shell metacharacter is rejected outright, and Adb.install_apk
    is never called with it.
    """
    resolved = Path("/host/ai_share/weird; rm -rf /.apk")
    monkeypatch.setattr(app_lifecycle, "resolve_confined_host_path", lambda p: resolved)

    called = []
    monkeypatch.setattr(Adb, "install_apk", staticmethod(called.append))

    with pytest.raises(ToolExecutionError, match="disallowed character"):
        app_lifecycle.install_apk("weird.apk")

    assert called == []


def test_install_apk_with_space_in_filename_is_not_quoted(monkeypatch):
    """Regression (review-caught bug): a space-containing (but otherwise
    metacharacter-free) apk_path must reach Adb.install_apk UNQUOTED -- a
    shlex.quote()-d path (e.g. "'/host/ai_share/my app.apk'") would make
    Adb.install_apk's internal, non-shell
    subprocess.run([aapt_path, "dump", "badging", apk_path]) call look for a
    literal path containing quote characters, which does not exist on disk,
    silently making aapt fail to resolve the package name even though the
    install itself succeeded.
    """
    resolved = Path("/host/ai_share/my app.apk")
    monkeypatch.setattr(app_lifecycle, "resolve_confined_host_path", lambda p: resolved)

    captured = {}

    def fake_install_apk(apk_path):
        captured["apk_path"] = apk_path
        # Simulate Adb.install_apk's real aapt call: it can only find the
        # real file (and thus resolve a package name) if apk_path is the
        # raw, unquoted path.
        return "com.example.app" if apk_path == str(resolved) else None

    monkeypatch.setattr(Adb, "install_apk", staticmethod(fake_install_apk))

    result = app_lifecycle.install_apk("my app.apk")

    assert captured["apk_path"] == str(resolved)  # unquoted -- no "'" added
    assert "'" not in captured["apk_path"]
    assert result == {"installed": True, "package_name": "com.example.app"}


def test_install_apk_path_outside_allowed_roots_propagates(monkeypatch):
    def fake_resolve(p):
        raise ToolExecutionError("path is outside every allowed host directory")

    monkeypatch.setattr(app_lifecycle, "resolve_confined_host_path", fake_resolve)

    with pytest.raises(ToolExecutionError, match="outside every allowed"):
        app_lifecycle.install_apk("/etc/passwd")


def test_install_apk_wraps_apkinstallerror(monkeypatch):
    monkeypatch.setattr(
        app_lifecycle, "resolve_confined_host_path", lambda p: Path("/host/app.apk")
    )

    def fake_install_apk(apk_path):
        raise APKInstallError("com.example.app", "signature mismatch")

    monkeypatch.setattr(Adb, "install_apk", staticmethod(fake_install_apk))

    with pytest.raises(ToolExecutionError, match="signature mismatch"):
        app_lifecycle.install_apk("app.apk")


# -- uninstall_apk -----------------------------------------------------------------


def test_uninstall_apk_success(monkeypatch):
    monkeypatch.setattr(Adb, "uninstall_apk", staticmethod(lambda package_name: True))

    assert app_lifecycle.uninstall_apk("com.example.app") == {
        "uninstalled": True,
        "package_name": "com.example.app",
    }


def test_uninstall_apk_failure(monkeypatch):
    monkeypatch.setattr(Adb, "uninstall_apk", staticmethod(lambda package_name: False))

    assert app_lifecycle.uninstall_apk("com.example.app") == {
        "uninstalled": False,
        "package_name": "com.example.app",
    }


def test_uninstall_apk_rejects_malicious_package_name(monkeypatch):
    """Regression: validate_package_name() rejects a package_name that
    doesn't match Android's package-identifier format BEFORE it ever reaches
    Adb.uninstall_apk -- stronger than shlex.quote()-ing it, since a
    validated name never needs quoting in the first place.
    """
    called = []
    monkeypatch.setattr(Adb, "uninstall_apk", staticmethod(called.append))

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        app_lifecycle.uninstall_apk("com.example.app; rm -rf /")

    assert called == []


def test_uninstall_apk_quotes_a_valid_package_name(monkeypatch):
    captured = {}

    def fake_uninstall(package_name):
        captured["package_name"] = package_name
        return True

    monkeypatch.setattr(Adb, "uninstall_apk", staticmethod(fake_uninstall))

    app_lifecycle.uninstall_apk("com.example.app")

    assert captured["package_name"] == "com.example.app"


# -- launch_app ---------------------------------------------------------------------


def test_launch_app_with_activity_quotes_both_arguments(monkeypatch):
    captured = {}

    def fake_launch_app(package_name, activity_name=None):
        captured["package_name"] = package_name
        captured["activity_name"] = activity_name
        return True, "Launched com.example.app"

    monkeypatch.setattr(Adb, "launch_app", staticmethod(fake_launch_app))

    result = app_lifecycle.launch_app("com.example.app", activity_name=".MainActivity")

    assert captured["package_name"] == "com.example.app"
    assert captured["activity_name"] == ".MainActivity"
    assert result == {
        "launched": True,
        "package_name": "com.example.app",
        "activity_name": ".MainActivity",
        "message": "Launched com.example.app",
    }


def test_launch_app_without_activity_passes_none_through(monkeypatch):
    captured = {}

    def fake_launch_app(package_name, activity_name=None):
        captured["activity_name"] = activity_name
        return True, "Launched"

    monkeypatch.setattr(Adb, "launch_app", staticmethod(fake_launch_app))

    result = app_lifecycle.launch_app("com.example.app")

    assert captured["activity_name"] is None
    assert result["activity_name"] is None


def test_launch_app_quotes_activity_name_with_shell_metacharacters(monkeypatch):
    captured = {}

    def fake_launch_app(package_name, activity_name=None):
        captured["activity_name"] = activity_name
        return True, "Launched"

    monkeypatch.setattr(Adb, "launch_app", staticmethod(fake_launch_app))

    app_lifecycle.launch_app("com.example.app", activity_name=".Main; rm -rf /")

    assert captured["activity_name"] == "'.Main; rm -rf /'"


def test_launch_app_rejects_malicious_package_name(monkeypatch):
    called = []
    monkeypatch.setattr(
        Adb,
        "launch_app",
        staticmethod(
            lambda package_name, activity_name=None: called.append(package_name)
        ),
    )

    with pytest.raises(ToolExecutionError, match="invalid package_name"):
        app_lifecycle.launch_app("com.example.app; rm -rf /")

    assert called == []


def test_launch_app_failure_surfaces_message(monkeypatch):
    monkeypatch.setattr(
        Adb,
        "launch_app",
        staticmethod(lambda package_name, activity_name=None: (False, "boom")),
    )

    result = app_lifecycle.launch_app("com.example.app")

    assert result["launched"] is False
    assert result["message"] == "boom"
