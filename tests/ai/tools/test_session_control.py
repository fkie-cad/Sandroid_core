"""Unit tests for sandroid.ai.tools.session_control.

Every service accessor used by ``session_control.py`` is imported lazily
inside each tool's own function body (see that module's docstring), which is
a deliberate convention so tests can monkeypatch the accessor on the module
it actually lives on rather than on ``session_control`` itself:

- ``get_spotlight_service`` -> monkeypatch ``sandroid.services`` (the
  package ``__init__``), same convention ``tests/ai/tools/test_app_query.py``
  and ``tests/ai/test_context.py`` use for sibling accessors.
- ``get_mitmproxy_service`` -> monkeypatch
  ``sandroid.services.mitmproxy_service`` directly -- this singleton is
  **not** re-exported from ``sandroid.services.__init__`` (unlike most other
  service accessors), so patching ``sandroid.services.get_mitmproxy_service``
  would silently patch nothing.
- ``get_proxy_service`` -> monkeypatch ``sandroid.services`` like
  ``get_spotlight_service``.
- ``ProxyManager``/``resolve_proxy_host_ip`` -> monkeypatch
  ``sandroid.core.proxy_manager`` directly. ``classify_device_proxy`` itself
  is a pure function of its three arguments (deterministic, no I/O), so
  tests exercise the real implementation rather than faking it -- it in turn
  reads ``resolve_proxy_host_ip`` as a module-level global, so patching that
  attribute on the ``proxy_manager`` module affects both the tool's own call
  and ``classify_device_proxy``'s internal call consistently.
"""

from types import SimpleNamespace

import pytest

from sandroid import services
from sandroid.ai.errors import ToolExecutionError
from sandroid.ai.tools import session_control
from sandroid.core import proxy_manager
from sandroid.core.enums import SpawnMode
from sandroid.core.proxy_manager import ProxyConfig, ProxyStatus
from sandroid.services import mitmproxy_service

# =============================================================================
# Fakes
# =============================================================================


class _FakeSpotlightService:
    """Records every mutating call (name + args) in call order."""

    def __init__(self, state: dict | None = None):
        self.calls: list[tuple] = []
        self._state = state or {
            "has_app": True,
            "package_name": "com.example.app",
            "activity_name": None,
            "pid": None,
            "mode": SpawnMode.ATTACH,
            "spawn_mode": False,
            "auto_resume": True,
            "set_at": None,
            # Legacy/internal fields that must never survive curation.
            "spawn_package": None,
            "spotlight_application": ("com.example.app", None),
            "spotlight_application_pid": None,
            "spotlight_spawn_application": None,
            "auto_resume_after_spawn": True,
            "spotlight_files": [],
            "spotlight_pull_one": None,
            "spotlight_pull_two": None,
        }

    def set_app(self, package_name, activity_name=None, pid=None, mode=None):
        self.calls.append(("set_app", package_name, activity_name, mode))

    def set_spawn_app(self, package_name, auto_resume=True):
        self.calls.append(("set_spawn_app", package_name))

    def set_spawn_mode(self, mode):
        self.calls.append(("set_spawn_mode", mode))

    def get_state_dict(self):
        return dict(self._state)


class _FakeMitmproxyState:
    def __init__(
        self,
        *,
        proxy_port=8080,
        web_port=8081,
        web_host="127.0.0.1",
        pid=None,
        flows_seen=0,
        tls_failures=0,
        last_error=None,
        running=False,
    ):
        self.proxy_port = proxy_port
        self.web_port = web_port
        self.web_host = web_host
        self.pid = pid
        self.flows_seen = flows_seen
        self.tls_failures = tls_failures
        self.last_error = last_error
        self.running = running


class _FakeMitmproxyService:
    def __init__(self, *, start_result=True, state=None):
        self.state = state or _FakeMitmproxyState()
        self._start_result = start_result
        self.stop_called = False

    def start(self):
        return self._start_result

    def stop(self):
        self.stop_called = True

    def is_running(self):
        return self.state.running


# =============================================================================
# set_spotlight_app
# =============================================================================


def test_set_spotlight_app_attach_calls_set_app_then_set_spawn_mode(monkeypatch):
    fake = _FakeSpotlightService()
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake)

    session_control.set_spotlight_app(
        "com.example.app", mode="attach", activity_name=".MainActivity"
    )

    assert fake.calls == [
        ("set_app", "com.example.app", ".MainActivity", SpawnMode.ATTACH),
        ("set_spawn_mode", False),
    ]


def test_set_spotlight_app_spawn_calls_set_spawn_app_only(monkeypatch):
    fake = _FakeSpotlightService()
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake)

    session_control.set_spotlight_app("com.example.app", mode="spawn")

    assert fake.calls == [("set_spawn_app", "com.example.app")]


def test_set_spotlight_app_invalid_mode_raises_without_touching_service(monkeypatch):
    def _unexpected_lookup():
        raise AssertionError(
            "get_spotlight_service must not be looked up for an invalid mode"
        )

    monkeypatch.setattr(services, "get_spotlight_service", _unexpected_lookup)

    with pytest.raises(ToolExecutionError):
        session_control.set_spotlight_app("com.example.app", mode="bogus")


def test_set_spotlight_app_returns_curated_state(monkeypatch):
    fake = _FakeSpotlightService(
        state={
            "has_app": True,
            "package_name": "com.example.app",
            "activity_name": ".MainActivity",
            "pid": None,
            "mode": SpawnMode.ATTACH,
            "spawn_mode": False,
            "auto_resume": True,
            "set_at": "2026-01-01T00:00:00",
            "spawn_package": None,
            "spotlight_application": ("com.example.app", ".MainActivity"),
            "spotlight_application_pid": None,
            "spotlight_spawn_application": None,
            "auto_resume_after_spawn": True,
            "spotlight_files": [],
            "spotlight_pull_one": None,
            "spotlight_pull_two": None,
        }
    )
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake)

    result = session_control.set_spotlight_app(
        "com.example.app", mode="attach", activity_name=".MainActivity"
    )

    assert result == {
        "has_app": True,
        "package_name": "com.example.app",
        "activity_name": ".MainActivity",
        "pid": None,
        "mode": "attach",
        "spawn_mode": False,
        "auto_resume": True,
        "set_at": "2026-01-01T00:00:00",
    }


# =============================================================================
# get_spotlight_app
# =============================================================================


def test_get_spotlight_app_excludes_legacy_fields_and_normalizes_enum(monkeypatch):
    fake = _FakeSpotlightService(
        state={
            "has_app": True,
            "package_name": "com.example.app",
            "activity_name": ".MainActivity",
            "pid": 1234,
            "mode": SpawnMode.SPAWN,
            "spawn_mode": True,
            "auto_resume": False,
            "set_at": None,
            # Legacy fields -- must be excluded from the curated result.
            "spawn_package": "com.example.app",
            "spotlight_application": None,
            "spotlight_application_pid": None,
            "spotlight_spawn_application": "com.example.app",
            "auto_resume_after_spawn": False,
            "spotlight_files": ["/sdcard/watched_file"],
            "spotlight_pull_one": {"stale": "data"},
            "spotlight_pull_two": {"stale": "data"},
        }
    )
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake)

    result = session_control.get_spotlight_app()

    assert result == {
        "has_app": True,
        "package_name": "com.example.app",
        "activity_name": ".MainActivity",
        "pid": 1234,
        "mode": "spawn",
        "spawn_mode": True,
        "auto_resume": False,
        "set_at": None,
    }
    assert isinstance(result["mode"], str)
    for legacy_field in (
        "spawn_package",
        "spotlight_application",
        "spotlight_application_pid",
        "spotlight_spawn_application",
        "auto_resume_after_spawn",
        "spotlight_files",
        "spotlight_pull_one",
        "spotlight_pull_two",
    ):
        assert legacy_field not in result


def test_get_spotlight_app_masks_stale_set_at_in_spawn_mode(monkeypatch):
    """Regression (found via E2E testing): SpotlightService.get_state_dict()
    only ever populates "set_at" from attach-mode state, so in spawn mode it
    can carry a stale timestamp left over from a *previous* attach call. The
    curated result must report None instead of that misleading value.
    """
    fake = _FakeSpotlightService(
        state={
            "has_app": True,
            "package_name": "com.spawned.app",
            "activity_name": None,
            "pid": None,
            "mode": SpawnMode.SPAWN,
            "spawn_mode": True,
            "auto_resume": True,
            "set_at": "2026-01-01T00:00:00",  # stale, from a prior attach call
            "spawn_package": "com.spawned.app",
            "spotlight_application": ("com.old.attach.app", None),
            "spotlight_application_pid": None,
            "spotlight_spawn_application": "com.spawned.app",
            "auto_resume_after_spawn": True,
            "spotlight_files": [],
            "spotlight_pull_one": None,
            "spotlight_pull_two": None,
        }
    )
    monkeypatch.setattr(services, "get_spotlight_service", lambda: fake)

    result = session_control.get_spotlight_app()

    assert result["set_at"] is None


# =============================================================================
# start_mitmproxy / stop_mitmproxy / get_mitmproxy_status
# =============================================================================


def test_start_mitmproxy_success_shape(monkeypatch):
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)
    fake = _FakeMitmproxyService(
        start_result=True, state=_FakeMitmproxyState(running=True)
    )
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy()

    assert result == {
        "started": True,
        "running": True,
        "proxy_port": 8080,
        "web_port": 8081,
        "web_host": "127.0.0.1",
        "error": None,
    }


def test_start_mitmproxy_surfaces_last_error_when_start_returns_false(monkeypatch):
    # "already running" is the benign no-op case: started=False but
    # running=True, error explains why -- not a real failure.
    state = _FakeMitmproxyState(last_error="already running", running=True)
    fake = _FakeMitmproxyService(start_result=False, state=state)
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy()

    assert result == {
        "started": False,
        "running": True,
        "proxy_port": 8080,
        "web_port": 8081,
        "web_host": "127.0.0.1",
        "error": "already running",
    }


def test_start_mitmproxy_settle_detects_post_start_crash(monkeypatch):
    """Regression (found via E2E testing): mitmweb can crash within ~1s of a
    successful Popen (e.g. its configured port is already bound by another
    process). An immediate is_running() check can miss this -- the tool
    settles briefly before trusting `running`, and must synthesize an error
    message when the service itself never recorded one.
    """
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)
    state = _FakeMitmproxyState(running=False, last_error=None)
    fake = _FakeMitmproxyService(start_result=True, state=state)
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy()

    assert result["started"] is True
    assert result["running"] is False
    assert result["error"] is not None
    assert "port" in result["error"].lower()


def test_stop_mitmproxy_already_stopped(monkeypatch):
    fake = _FakeMitmproxyService(state=_FakeMitmproxyState(running=False))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.stop_mitmproxy()

    assert result == {"stopped": True, "was_running": False}


def test_stop_mitmproxy_stops_a_running_instance(monkeypatch):
    # is_running() reads state.running; simulate stop() flipping it off, the
    # way the real MitmproxyService.stop() does before returning.
    state = _FakeMitmproxyState(running=True)

    class _StoppingFakeService(_FakeMitmproxyService):
        def stop(self):
            super().stop()
            self.state.running = False

    fake = _StoppingFakeService(state=state)
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.stop_mitmproxy()

    assert result == {"stopped": True, "was_running": True}
    assert fake.stop_called is True


def test_get_mitmproxy_status_prefers_is_running_over_state_running(monkeypatch):
    # state.running disagrees with is_running() -- the tool must trust
    # is_running() as ground truth, not the (possibly stale) state field.
    state = _FakeMitmproxyState(
        proxy_port=9090,
        web_port=9091,
        web_host="0.0.0.0",
        pid=555,
        flows_seen=3,
        tls_failures=1,
        last_error=None,
        running=True,
    )
    fake = _FakeMitmproxyService(state=state)
    fake.is_running = lambda: False
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.get_mitmproxy_status()

    assert result == {
        "running": False,
        "proxy_port": 9090,
        "web_port": 9091,
        "web_host": "0.0.0.0",
        "pid": 555,
        "flows_seen": 3,
        "tls_failures": 1,
        "last_error": None,
    }


# =============================================================================
# set_device_proxy
# =============================================================================


def test_set_device_proxy_resolves_host_and_port_and_calls_set_proxy(monkeypatch):
    monkeypatch.setattr(proxy_manager, "resolve_proxy_host_ip", lambda: "10.0.2.2")
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(get_proxy_settings=lambda: (ProxyStatus.NOT_SET, None)),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=9999))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)

    captured = {}

    def fake_set_proxy(ip, port):
        captured["ip"] = ip
        captured["port"] = port
        return True

    monkeypatch.setattr(
        services,
        "get_proxy_service",
        lambda: SimpleNamespace(set_proxy=fake_set_proxy),
    )

    result = session_control.set_device_proxy()

    assert captured == {"ip": "10.0.2.2", "port": "9999"}
    assert result == {
        "success": True,
        "host_ip": "10.0.2.2",
        "port": 9999,
        "overwrote_foreign_proxy": False,
        "previous_proxy": None,
    }


def test_set_device_proxy_detects_overwritten_foreign_proxy(monkeypatch):
    monkeypatch.setattr(proxy_manager, "resolve_proxy_host_ip", lambda: "10.0.2.2")
    foreign_cfg = ProxyConfig(ip="1.2.3.4", port=9999)
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(
            get_proxy_settings=lambda: (ProxyStatus.SET, foreign_cfg)
        ),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)
    monkeypatch.setattr(
        services,
        "get_proxy_service",
        lambda: SimpleNamespace(set_proxy=lambda ip, port: True),
    )

    result = session_control.set_device_proxy()

    assert result["overwrote_foreign_proxy"] is True
    assert result["previous_proxy"] == "1.2.3.4:9999"


def test_set_device_proxy_never_raises_when_set_proxy_fails(monkeypatch):
    monkeypatch.setattr(proxy_manager, "resolve_proxy_host_ip", lambda: "10.0.2.2")
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(get_proxy_settings=lambda: (ProxyStatus.NOT_SET, None)),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)
    monkeypatch.setattr(
        services,
        "get_proxy_service",
        lambda: SimpleNamespace(set_proxy=lambda ip, port: False),
    )

    result = session_control.set_device_proxy()

    assert result["success"] is False


# =============================================================================
# clear_device_proxy
# =============================================================================


def test_clear_device_proxy_passes_through_true(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_proxy_service",
        lambda: SimpleNamespace(clear_proxy=lambda: True),
    )

    assert session_control.clear_device_proxy() == {"success": True}


def test_clear_device_proxy_passes_through_false(monkeypatch):
    monkeypatch.setattr(
        services,
        "get_proxy_service",
        lambda: SimpleNamespace(clear_proxy=lambda: False),
    )

    assert session_control.clear_device_proxy() == {"success": False}


# =============================================================================
# get_device_proxy_status
# =============================================================================


def test_get_device_proxy_status_ours(monkeypatch):
    monkeypatch.setattr(proxy_manager, "resolve_proxy_host_ip", lambda: "10.0.2.2")
    ours_cfg = ProxyConfig(ip="10.0.2.2", port=8080)
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(get_proxy_settings=lambda: (ProxyStatus.SET, ours_cfg)),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)

    result = session_control.get_device_proxy_status()

    assert result == {
        "state": "ours",
        "addr": "10.0.2.2:8080",
        "mitmproxy_proxy_port": 8080,
    }


def test_get_device_proxy_status_other(monkeypatch):
    monkeypatch.setattr(proxy_manager, "resolve_proxy_host_ip", lambda: "10.0.2.2")
    other_cfg = ProxyConfig(ip="192.168.1.50", port=8888)
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(
            get_proxy_settings=lambda: (ProxyStatus.SET, other_cfg)
        ),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)

    result = session_control.get_device_proxy_status()

    assert result == {
        "state": "other",
        "addr": "192.168.1.50:8888",
        "mitmproxy_proxy_port": 8080,
    }


def test_get_device_proxy_status_none_when_not_set(monkeypatch):
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(get_proxy_settings=lambda: (ProxyStatus.NOT_SET, None)),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)

    result = session_control.get_device_proxy_status()

    assert result == {"state": "none", "addr": "", "mitmproxy_proxy_port": 8080}


def test_get_device_proxy_status_none_when_error(monkeypatch):
    monkeypatch.setattr(
        proxy_manager,
        "ProxyManager",
        lambda: SimpleNamespace(get_proxy_settings=lambda: (ProxyStatus.ERROR, None)),
    )
    fake_mitm = _FakeMitmproxyService(state=_FakeMitmproxyState(proxy_port=8080))
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake_mitm)

    result = session_control.get_device_proxy_status()

    assert result == {"state": "none", "addr": "", "mitmproxy_proxy_port": 8080}
