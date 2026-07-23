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
- ``get_focus_manager`` -> monkeypatch ``sandroid.core.proxy_manager``
  directly, same as ``ProxyManager`` above.
- ``get_config`` (App-Proxy tools only) -> monkeypatch ``sandroid.config``
  directly (the module ``get_config`` is defined on).
- ``_current_owner_id`` (the resource-arbiter owner ``ContextVar`` App-Proxy
  tools read via a lazy ``from sandroid.ai.loop import _current_owner_id``)
  -> tests import the very same ``ContextVar`` object from
  ``sandroid.ai.loop`` and drive it directly with ``.set()``/``.reset()``
  (see the ``_as_owner`` context manager below); a lazy import re-fetches the
  same singleton object from ``sys.modules``, so this affects the tool's own
  read too, not just the test's.
"""

from types import SimpleNamespace

import pytest

from sandroid import config as sandroid_config
from sandroid import services
from sandroid.ai import loop as ai_loop
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
        flow_errors=0,
        last_error=None,
        running=False,
    ):
        self.proxy_port = proxy_port
        self.web_port = web_port
        self.web_host = web_host
        self.pid = pid
        self.flows_seen = flows_seen
        self.tls_failures = tls_failures
        self.flow_errors = flow_errors
        self.last_error = last_error
        self.running = running


class _FakeMitmproxyService:
    def __init__(self, *, start_result=True, state=None):
        self.state = state or _FakeMitmproxyState()
        self._start_result = start_result
        self.stop_called = False
        # Records the exact (proxy_port, web_port, web_host) kwargs the last
        # start() call was made with, so tests can assert session_control
        # always forwards three concrete values -- never bare defaults.
        self.start_calls: list[tuple] = []

    def start(self, proxy_port=8080, web_port=8081, web_host="127.0.0.1"):
        self.start_calls.append((proxy_port, web_port, web_host))
        if self._start_result:
            self.state.proxy_port = proxy_port
            self.state.web_port = web_port
            self.state.web_host = web_host
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


def _mock_mitmproxy_config(
    monkeypatch, *, proxy_port=8080, web_port=8081, web_host="127.0.0.1"
):
    """Monkeypatch ``get_config().mitmproxy`` with fixed, known port values.

    Every ``start_mitmproxy`` test needs this -- unlike the other tools in
    this module, ``start_mitmproxy`` now reads config itself (via
    ``_resolve_mitmproxy_start_ports``) whenever a port argument is omitted,
    so leaving this unmocked would fall through to the real
    ``sandroid.config.get_config()`` singleton and make the test depend on
    whatever config happens to be cached/on disk.
    """
    monkeypatch.setattr(
        sandroid_config,
        "get_config",
        lambda: SimpleNamespace(
            mitmproxy=SimpleNamespace(
                proxy_port=proxy_port, web_port=web_port, web_host=web_host
            )
        ),
    )


def test_start_mitmproxy_success_shape(monkeypatch):
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)
    _mock_mitmproxy_config(monkeypatch)
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
    assert fake.start_calls == [(8080, 8081, "127.0.0.1")]


def test_start_mitmproxy_surfaces_last_error_when_start_returns_false(monkeypatch):
    # "already running" is the benign no-op case: started=False but
    # running=True, error explains why -- not a real failure.
    _mock_mitmproxy_config(monkeypatch)
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
    _mock_mitmproxy_config(monkeypatch)
    state = _FakeMitmproxyState(running=False, last_error=None)
    fake = _FakeMitmproxyService(start_result=True, state=state)
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy()

    assert result["started"] is True
    assert result["running"] is False
    assert result["error"] is not None
    assert "port" in result["error"].lower()
    # The synthesized error must tell the model what lever to pull instead
    # of blindly retrying the identical call (the real-world failure mode
    # this tool exists to fix).
    assert "proxy_port" in result["error"]
    assert "web_port" in result["error"]


def test_start_mitmproxy_explicit_ports_forwarded_as_concrete_ints(monkeypatch):
    """Explicit proxy_port/web_port must win over whatever config says, and
    be forwarded to MitmproxyService.start() verbatim as concrete ints --
    even though config (here deliberately set to two DIFFERENT port numbers)
    is still consulted for web_host, since that is never an overridable tool
    argument.
    """
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)
    _mock_mitmproxy_config(
        monkeypatch, proxy_port=1111, web_port=2222, web_host="0.0.0.0"
    )
    fake = _FakeMitmproxyService(
        start_result=True, state=_FakeMitmproxyState(running=True)
    )
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy(proxy_port=18080, web_port=18081)

    assert fake.start_calls == [(18080, 18081, "0.0.0.0")]
    assert result["proxy_port"] == 18080
    assert result["web_port"] == 18081


def test_start_mitmproxy_partial_override_does_not_drop_the_other_configured_port(
    monkeypatch,
):
    """Regression (the sentinel-matching trap): passing only proxy_port must
    not silently revert web_port to MitmproxyService.start()'s hardcoded
    default (8081) instead of the value actually configured -- and
    vice-versa.
    """
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)
    _mock_mitmproxy_config(
        monkeypatch, proxy_port=9999, web_port=9998, web_host="0.0.0.0"
    )
    fake = _FakeMitmproxyService(
        start_result=True, state=_FakeMitmproxyState(running=True)
    )
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    # Only proxy_port supplied -- web_port must come from config (9998), not
    # the hardcoded default (8081).
    session_control.start_mitmproxy(proxy_port=18080)
    assert fake.start_calls == [(18080, 9998, "0.0.0.0")]

    fake.start_calls.clear()

    # Only web_port supplied -- proxy_port must come from config (9999), not
    # the hardcoded default (8080).
    session_control.start_mitmproxy(web_port=18081)
    assert fake.start_calls == [(9999, 18081, "0.0.0.0")]


def test_start_mitmproxy_falls_back_to_hardcoded_defaults_when_config_unavailable(
    monkeypatch,
):
    """Defensive fallback: if get_config() itself raises, omitted ports must
    still resolve to MitmproxyService.start()'s own hardcoded defaults
    (8080/8081/"127.0.0.1"), mirroring the try/except already around that
    same read in mitmproxy_service.py, rather than propagating the
    exception.
    """
    monkeypatch.setattr(session_control.time, "sleep", lambda _s: None)

    def _raising_get_config():
        raise RuntimeError("config unavailable")

    monkeypatch.setattr(sandroid_config, "get_config", _raising_get_config)
    fake = _FakeMitmproxyService(
        start_result=True, state=_FakeMitmproxyState(running=True)
    )
    monkeypatch.setattr(mitmproxy_service, "get_mitmproxy_service", lambda: fake)

    result = session_control.start_mitmproxy()

    assert fake.start_calls == [(8080, 8081, "127.0.0.1")]
    assert result["started"] is True


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
        flow_errors=2,
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
        "flow_errors": 2,
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


# =============================================================================
# App proxies (Focus lanes): fakes + helpers
# =============================================================================


class _FakeFocusManager:
    """Records ``enable_focus``/``disable_focus``/``set_quic_blocking`` calls
    in order and mirrors the real ``FocusManager``'s ``(ok, message)``
    return shape, plus ``app_proxies()``/``lane_for()`` reads over the same
    in-memory ``{package: target}`` state -- close enough to the real
    ``FocusManager`` for these tools' own dispatch logic (which never
    inspects ``FocusManager`` internals beyond its public API).
    """

    def __init__(
        self,
        *,
        lanes: dict[str, str] | None = None,
        spotlight_package: str | None = "com.spotlighted.app",
        lane_ports: dict[str, int] | None = None,
    ):
        self._apps: dict[str, str] = dict(lanes or {})
        self._spotlight_package = spotlight_package
        self._lane_ports = dict(lane_ports or {})
        self.enable_calls: list[tuple] = []
        self.disable_calls: list = []
        self.quic_calls: list[bool] = []

    def enable_focus(self, package=None, target=None):
        self.enable_calls.append((package, target))
        pkg = package or self._spotlight_package
        if not pkg:
            return False, "No spotlight app set — pick one first."
        if pkg in self._apps:
            return True, f"{pkg} already proxied"
        self._apps[pkg] = "ours" if target is None else target
        label = pkg if target is None else f"{pkg} -> {target}"
        return True, f"App proxy -> {label} (lane 0)"

    def disable_focus(self, package=None):
        self.disable_calls.append(package)
        if package is None:
            if not self._apps:
                return True, "No app proxies to disable"
            self._apps.clear()
            return True, "App proxies disabled (all lanes freed)"
        if package not in self._apps:
            return True, f"{package} has no app proxy"
        del self._apps[package]
        return True, f"App proxy removed for {package}"

    def app_proxies(self):
        return dict(self._apps)

    def lane_for(self, package):
        # Matches the real FocusManager's contract: None for a package with
        # no active lane, not just a default port irrespective of state --
        # enable_app_proxy's own "was this already active before this call"
        # pre-check relies on that distinction.
        if package not in self._apps:
            return None
        return self._lane_ports.get(package, 8082)

    def set_quic_blocking(self, enabled):
        self.quic_calls.append(enabled)


def _as_owner(owner_id: str | None):
    """Context manager: run the block with ``_current_owner_id`` set.

    Drives the *actual* ``ContextVar`` App-Proxy tools read (imported lazily
    inside each tool as ``from sandroid.ai.loop import _current_owner_id`` --
    the same singleton object as ``ai_loop._current_owner_id`` here), then
    restores the previous value on exit via the token, mirroring
    ``sandroid.ai.loop.run_agent_turn``'s own set/reset pairing.
    """

    class _OwnerContext:
        def __enter__(self):
            self._token = ai_loop._current_owner_id.set(owner_id)
            return self

        def __exit__(self, *exc_info):
            ai_loop._current_owner_id.reset(self._token)

    return _OwnerContext()


@pytest.fixture(autouse=True)
def _reset_app_proxy_ownership():
    """Isolate the module-level ownership map across tests in this file."""
    session_control._app_proxy_owner_by_package.clear()
    yield
    session_control._app_proxy_owner_by_package.clear()


# =============================================================================
# enable_app_proxy
# =============================================================================


def test_enable_app_proxy_success_records_ownership(monkeypatch):
    fake = _FakeFocusManager()
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    with _as_owner("owner-A"):
        result = session_control.enable_app_proxy(package="com.example.app")

    assert result == {
        "success": True,
        "message": "App proxy -> com.example.app (lane 0)",
        "package": "com.example.app",
        "target": None,
        "lane_socks_port": 8082,
    }
    assert fake.enable_calls == [("com.example.app", None)]
    assert session_control._app_proxy_owner_by_package == {"com.example.app": "owner-A"}


def test_enable_app_proxy_resolves_spotlight_app_when_package_omitted(monkeypatch):
    fake = _FakeFocusManager(spotlight_package="com.spotlighted.app")
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: "com.spotlighted.app"),
    )

    with _as_owner("owner-A"):
        result = session_control.enable_app_proxy()

    assert result["success"] is True
    assert result["package"] == "com.spotlighted.app"
    assert session_control._app_proxy_owner_by_package == {
        "com.spotlighted.app": "owner-A"
    }


def test_enable_app_proxy_no_spotlight_app_fails_without_recording_ownership(
    monkeypatch,
):
    fake = _FakeFocusManager(spotlight_package=None)
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    monkeypatch.setattr(
        services,
        "get_spotlight_service",
        lambda: SimpleNamespace(get_effective_package=lambda: None),
    )

    with _as_owner("owner-A"):
        result = session_control.enable_app_proxy()

    assert result["success"] is False
    assert result["package"] is None
    assert result["lane_socks_port"] is None
    assert session_control._app_proxy_owner_by_package == {}


def test_enable_app_proxy_already_proxied_is_idempotent(monkeypatch):
    fake = _FakeFocusManager(lanes={"com.example.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    result = session_control.enable_app_proxy(package="com.example.app")

    assert result["success"] is True
    assert "already proxied" in result["message"]
    assert result["package"] == "com.example.app"
    assert result["lane_socks_port"] == 8082


def test_enable_app_proxy_idempotent_hit_never_adopts_a_foreign_owned_lane(
    monkeypatch,
):
    # Regression: a lane already active (whether TUI-created, i.e. no
    # ownership entry at all, or created by a *different* owner) must not be
    # silently "adopted" into the calling owner's ownership map just
    # because enable_focus's idempotent branch reports success. Otherwise
    # this owner's later unscoped disable_app_proxy would tear down a lane
    # it never actually created.
    fake = _FakeFocusManager(lanes={"com.example.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.example.app"] = "owner-A"

    with _as_owner("owner-B"):
        result = session_control.enable_app_proxy(package="com.example.app")

    assert result["success"] is True
    assert session_control._app_proxy_owner_by_package == {"com.example.app": "owner-A"}


def test_enable_app_proxy_idempotent_hit_on_tui_created_lane_stays_unowned(
    monkeypatch,
):
    # Same regression, but for a lane with NO ownership entry at all (the
    # TUI-created case) -- an idempotent re-enable must not create one.
    fake = _FakeFocusManager(lanes={"com.example.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    with _as_owner("owner-A"):
        result = session_control.enable_app_proxy(package="com.example.app")

    assert result["success"] is True
    assert session_control._app_proxy_owner_by_package == {}


def test_enable_app_proxy_external_target_reported_and_not_recorded_as_ours(
    monkeypatch,
):
    fake = _FakeFocusManager()
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    result = session_control.enable_app_proxy(
        package="com.example.app", target="http://127.0.0.1:8888"
    )

    assert result["success"] is True
    assert result["target"] == "http://127.0.0.1:8888"
    assert fake.app_proxies() == {"com.example.app": "http://127.0.0.1:8888"}


def test_enable_app_proxy_no_owner_context_never_records_ownership(monkeypatch):
    fake = _FakeFocusManager()
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    # No _as_owner context -- _current_owner_id.get() is None here.
    result = session_control.enable_app_proxy(package="com.example.app")

    assert result["success"] is True
    assert session_control._app_proxy_owner_by_package == {}


# =============================================================================
# disable_app_proxy
# =============================================================================


def test_disable_app_proxy_named_package_always_allowed(monkeypatch):
    fake = _FakeFocusManager(lanes={"com.example.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.example.app"] = "owner-A"

    # Called under a DIFFERENT owner -- a named package is always allowed,
    # regardless of ownership.
    with _as_owner("owner-B"):
        result = session_control.disable_app_proxy(package="com.example.app")

    assert result == {
        "success": True,
        "message": "App proxy removed for com.example.app",
        "package": "com.example.app",
        "scope": "one",
    }
    assert fake.disable_calls == ["com.example.app"]
    assert "com.example.app" not in session_control._app_proxy_owner_by_package


def test_disable_app_proxy_named_package_idempotent_when_not_proxied(monkeypatch):
    fake = _FakeFocusManager(lanes={})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)

    result = session_control.disable_app_proxy(package="com.example.app")

    assert result["success"] is True
    assert result["scope"] == "one"


def test_disable_app_proxy_default_scope_only_frees_callers_own_lanes(monkeypatch):
    """Regression: two packages enabled under two different simulated owner
    contexts -- an unscoped disable_app_proxy(package=None) call made under
    owner A must only free A's lane; B's lane must survive untouched.
    """
    fake = _FakeFocusManager(lanes={"com.a.app": "ours", "com.b.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.a.app"] = "owner-A"
    session_control._app_proxy_owner_by_package["com.b.app"] = "owner-B"

    with _as_owner("owner-A"):
        result = session_control.disable_app_proxy()

    assert result["scope"] == "own"
    assert result["package"] is None
    assert result["freed"] == ["com.a.app"]
    assert fake.disable_calls == ["com.a.app"]
    assert fake.app_proxies() == {"com.b.app": "ours"}
    assert "com.a.app" not in session_control._app_proxy_owner_by_package
    assert session_control._app_proxy_owner_by_package["com.b.app"] == "owner-B"


def test_disable_app_proxy_force_frees_everything_regardless_of_owner(monkeypatch):
    fake = _FakeFocusManager(lanes={"com.a.app": "ours", "com.b.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.a.app"] = "owner-A"
    session_control._app_proxy_owner_by_package["com.b.app"] = "owner-B"

    with _as_owner("owner-A"):
        result = session_control.disable_app_proxy(force=True)

    assert result["scope"] == "all"
    assert result["package"] is None
    assert fake.disable_calls == [None]
    assert fake.app_proxies() == {}
    assert session_control._app_proxy_owner_by_package == {}


def test_disable_app_proxy_no_owner_context_falls_back_to_blanket(monkeypatch):
    fake = _FakeFocusManager(lanes={"com.a.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.a.app"] = "owner-A"

    # No _as_owner context -- _current_owner_id.get() is None here, so even
    # though force=False, there is no owner to scope the teardown to.
    result = session_control.disable_app_proxy()

    assert result["scope"] == "all"
    assert fake.disable_calls == [None]
    assert fake.app_proxies() == {}
    assert session_control._app_proxy_owner_by_package == {}


def test_disable_app_proxy_never_touches_tui_created_lane(monkeypatch):
    """A lane present in FocusManager but absent from
    _app_proxy_owner_by_package (simulating a TUI-created lane) must survive
    an unscoped disable_app_proxy(package=None) call.
    """
    fake = _FakeFocusManager(lanes={"com.owned.app": "ours", "com.tui.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    session_control._app_proxy_owner_by_package["com.owned.app"] = "owner-A"
    # com.tui.app deliberately has no ownership entry.

    with _as_owner("owner-A"):
        result = session_control.disable_app_proxy()

    assert result["scope"] == "own"
    assert result["freed"] == ["com.owned.app"]
    assert fake.disable_calls == ["com.owned.app"]
    assert fake.app_proxies() == {"com.tui.app": "ours"}


def test_disable_app_proxy_own_scope_with_no_owned_lanes_is_a_benign_no_op(
    monkeypatch,
):
    fake = _FakeFocusManager(lanes={"com.tui.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    # No ownership entries at all -- everything live is TUI/foreign-owned.

    with _as_owner("owner-A"):
        result = session_control.disable_app_proxy()

    assert result["success"] is True
    assert result["scope"] == "own"
    assert result["freed"] == []
    assert fake.disable_calls == []
    assert fake.app_proxies() == {"com.tui.app": "ours"}


# =============================================================================
# get_app_proxy_status
# =============================================================================


def test_get_app_proxy_status_shape_and_owned_by_caller(monkeypatch):
    fake = _FakeFocusManager(
        lanes={"com.a.app": "ours", "com.b.app": "http://1.2.3.4:8888"}
    )
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    monkeypatch.setattr(
        sandroid_config,
        "get_config",
        lambda: SimpleNamespace(mitmproxy=SimpleNamespace(focus_lanes=5)),
    )
    # com.a.app is owned by the calling owner; com.b.app has no entry at all
    # (simulating a TUI-created or foreign-owned lane).
    session_control._app_proxy_owner_by_package["com.a.app"] = "owner-A"

    with _as_owner("owner-A"):
        result = session_control.get_app_proxy_status()

    assert result == {
        "active": True,
        "apps": {
            "com.a.app": {"target": "ours", "owned_by_caller": True},
            "com.b.app": {
                "target": "http://1.2.3.4:8888",
                "owned_by_caller": False,
            },
        },
        "lanes_used": 2,
        "lanes_total": 5,
        "lanes_free": 3,
    }


def test_get_app_proxy_status_empty_when_no_lanes_active(monkeypatch):
    fake = _FakeFocusManager(lanes={})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    monkeypatch.setattr(
        sandroid_config,
        "get_config",
        lambda: SimpleNamespace(mitmproxy=SimpleNamespace(focus_lanes=5)),
    )

    result = session_control.get_app_proxy_status()

    assert result == {
        "active": False,
        "apps": {},
        "lanes_used": 0,
        "lanes_total": 5,
        "lanes_free": 5,
    }


def test_get_app_proxy_status_owned_by_caller_false_with_no_owner_context(
    monkeypatch,
):
    """A lane recorded as owned by some owner must report
    owned_by_caller=False when THIS call has no owner context at all --
    None must never spuriously match an absent/foreign ownership entry.
    """
    fake = _FakeFocusManager(lanes={"com.a.app": "ours"})
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake)
    monkeypatch.setattr(
        sandroid_config,
        "get_config",
        lambda: SimpleNamespace(mitmproxy=SimpleNamespace(focus_lanes=5)),
    )
    # No ownership entry recorded for com.a.app at all.

    result = session_control.get_app_proxy_status()

    assert result["apps"]["com.a.app"]["owned_by_caller"] is False


# =============================================================================
# set_app_proxy_quic_blocking
# =============================================================================


def test_set_app_proxy_quic_blocking_persists_config_before_calling_manager(
    monkeypatch,
):
    """Regression: the config value must already be committed by the time
    FocusManager.set_quic_blocking() runs, mirroring proxy_modal.py's own
    commit order -- so lanes enabled after this call also pick it up.
    """
    fake_focus_cfg = SimpleNamespace(block_quic=False)
    fake_cfg = SimpleNamespace(focus=fake_focus_cfg)
    monkeypatch.setattr(sandroid_config, "get_config", lambda: fake_cfg)

    seen_during_call = {}

    class _OrderCheckingFocusManager:
        def set_quic_blocking(self, enabled):
            seen_during_call["enabled_arg"] = enabled
            seen_during_call["config_value_at_call_time"] = fake_focus_cfg.block_quic

    monkeypatch.setattr(proxy_manager, "get_focus_manager", _OrderCheckingFocusManager)

    result = session_control.set_app_proxy_quic_blocking(True)

    assert result == {"success": True, "enabled": True}
    assert fake_focus_cfg.block_quic is True
    assert seen_during_call == {
        "enabled_arg": True,
        "config_value_at_call_time": True,
    }


def test_set_app_proxy_quic_blocking_false(monkeypatch):
    fake_focus_cfg = SimpleNamespace(block_quic=True)
    fake_cfg = SimpleNamespace(focus=fake_focus_cfg)
    monkeypatch.setattr(sandroid_config, "get_config", lambda: fake_cfg)
    fake_manager = _FakeFocusManager()
    monkeypatch.setattr(proxy_manager, "get_focus_manager", lambda: fake_manager)

    result = session_control.set_app_proxy_quic_blocking(False)

    assert result == {"success": True, "enabled": False}
    assert fake_focus_cfg.block_quic is False
    assert fake_manager.quic_calls == [False]
