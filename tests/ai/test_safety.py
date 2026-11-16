"""Tests for the AI Chat safety defaults (sandroid.ai.safety and friends).

Covers: off-unless-configured, localhost-only egress policy, the egress
notice, secret redaction (helper, client errors, config persistence), the
tool-permission defaults, and the experimental labelling of the Frida
bypasses. No network, no device.
"""

from types import SimpleNamespace

import pytest
import requests

from sandroid.ai import safety
from sandroid.ai.client import OpenAIClient
from sandroid.ai.errors import AIClientError
from sandroid.ai.safety import (
    API_KEY_ENV_VAR,
    AISettings,
    api_key_source,
    build_client,
    egress_notice_lines,
    get_ai_settings,
    is_loopback_url,
    redact_secrets,
)
from sandroid.config.schema import AIConfig

LOCAL = "http://localhost:11434/v1"
REMOTE = "https://api.example.com/v1"
KEY = "sk-test-SECRET-0123456789abcdef"


def _ai(**kw):
    base = {"base_url": LOCAL, "api_key": KEY, "model": "qwen2.5"}
    base.update(kw)
    return SimpleNamespace(**base)


# -- loopback detection --------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434/v1",
        "http://LOCALHOST/v1",
        "http://127.0.0.1:8000/v1",
        "http://127.8.9.10/v1",
        "http://[::1]:8000/v1",
        "http://ollama.localhost/v1",
    ],
)
def test_loopback_urls_are_local(url):
    assert is_loopback_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "not a url",
        "https://api.openai.com/v1",
        "http://192.168.1.10:11434/v1",  # LAN is NOT local: data leaves the host
        "http://10.0.0.5/v1",
        "http://localhost.evil.com/v1",
        "http://127.0.0.1.nip.io/v1",
    ],
)
def test_non_loopback_urls_are_remote(url):
    assert is_loopback_url(url) is False


# -- off unless configured / remote policy ---------------------------------------


def test_aiconfig_defaults_are_off_and_local_only():
    cfg = AIConfig()
    assert cfg.base_url is None
    assert cfg.api_key is None
    assert cfg.model is None
    assert cfg.allow_remote is False
    assert get_ai_settings(cfg).is_ready is False


def test_api_key_never_in_config_repr():
    cfg = AIConfig(base_url=LOCAL, api_key=KEY, model="m")
    assert KEY not in repr(cfg)
    assert KEY not in str(cfg)
    assert KEY not in repr(get_ai_settings(cfg))


@pytest.mark.parametrize("missing", ["base_url", "api_key", "model"])
def test_each_missing_field_means_not_configured(missing):
    settings = get_ai_settings(_ai(**{missing: None}))
    assert settings.is_configured is False
    assert settings.is_ready is False
    assert f"ai.{missing}" in settings.problem
    assert "not configured" in settings.problem


def test_none_or_absent_config_is_not_configured():
    assert get_ai_settings(None).is_ready is False
    assert get_ai_settings(SimpleNamespace()).is_ready is False


def test_blank_strings_count_as_missing():
    assert get_ai_settings(_ai(model="   ")).missing_fields == ["model"]


def test_local_endpoint_is_ready():
    settings = get_ai_settings(_ai())
    assert settings.is_ready
    assert settings.problem is None


def test_remote_endpoint_refused_by_default():
    settings = get_ai_settings(_ai(base_url=REMOTE))
    assert settings.is_configured is True
    assert settings.is_ready is False
    assert "allow_remote" in settings.problem
    assert "api.example.com" in settings.problem


def test_remote_endpoint_allowed_only_with_explicit_true():
    assert get_ai_settings(_ai(base_url=REMOTE, allow_remote=True)).is_ready
    # A truthy non-bool (e.g. a stray string) is not an explicit opt-in.
    assert not get_ai_settings(_ai(base_url=REMOTE, allow_remote="yes")).is_ready


def test_non_http_scheme_refused():
    settings = get_ai_settings(_ai(base_url="file:///etc/passwd"))
    assert settings.is_ready is False
    assert "http" in settings.problem


def test_get_ai_settings_reads_toolbox_config(monkeypatch):
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=_ai()), raising=False)
    assert get_ai_settings().is_ready
    monkeypatch.setattr(Toolbox, "config", None, raising=False)
    assert get_ai_settings().is_ready is False


def test_build_client_refuses_unconfigured_and_remote():
    with pytest.raises(AIClientError, match="not configured"):
        build_client(AISettings())
    with pytest.raises(AIClientError, match="allow_remote"):
        build_client(get_ai_settings(_ai(base_url=REMOTE)))
    assert isinstance(build_client(get_ai_settings(_ai())), OpenAIClient)


def test_subtask_default_client_factory_applies_policy(monkeypatch):
    from sandroid.ai import subtasks
    from sandroid.core.toolbox import Toolbox

    monkeypatch.setattr(
        Toolbox, "config", SimpleNamespace(ai=_ai(base_url=REMOTE)), raising=False
    )
    with pytest.raises(AIClientError):
        subtasks._default_client_factory()
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=_ai()), raising=False)
    assert isinstance(subtasks._default_client_factory(), OpenAIClient)


# -- egress notice -------------------------------------------------------------


def test_notice_for_unconfigured_is_experimental_and_recommends_local():
    text = "\n".join(egress_notice_lines(AISettings()))
    assert "EXPERIMENTAL" in text
    assert "not configured" in text
    assert "Ollama" in text
    assert "vLLM" in text


def test_notice_names_local_endpoint_and_model(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, KEY)
    text = "\n".join(egress_notice_lines(get_ai_settings(_ai())))
    assert "EXPERIMENTAL" in text
    assert "LOCAL" in text
    assert "http://localhost:11434/v1" in text
    assert "qwen2.5" in text
    assert "device and app data" in text
    assert "plaintext" not in text  # key came from the env var
    assert KEY not in text


def test_notice_warns_loudly_for_remote_opt_in():
    settings = get_ai_settings(_ai(base_url=REMOTE, allow_remote=True))
    text = "\n".join(egress_notice_lines(settings))
    assert "REMOTE" in text
    assert "LEAVES this machine" in text


def test_notice_strips_credentials_from_endpoint():
    settings = get_ai_settings(_ai(base_url="http://user:pw@localhost:1/v1?key=abc"))
    text = "\n".join(egress_notice_lines(settings))
    assert "pw" not in text
    assert "abc" not in text
    assert "http://localhost:1/v1" in text


def test_plaintext_key_warning_when_key_comes_from_config(monkeypatch):
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    settings = get_ai_settings(_ai())
    assert api_key_source(settings) == "config"
    assert "plaintext" in "\n".join(egress_notice_lines(settings))
    monkeypatch.setenv(API_KEY_ENV_VAR, KEY)
    assert api_key_source(settings) == "env"
    assert api_key_source(AISettings()) is None


# -- redaction -------------------------------------------------------------------


def test_redacts_explicit_secret():
    out = redact_secrets(f"failed with key {KEY}!", [KEY])
    assert KEY not in out
    assert "***" in out


def test_redacts_configured_key_by_default(monkeypatch):
    from sandroid.core.toolbox import Toolbox

    key = "plain-config-key-without-prefix"
    monkeypatch.setattr(
        Toolbox, "config", SimpleNamespace(ai=_ai(api_key=key)), raising=False
    )
    assert key not in redact_secrets(f"oops {key}")


def test_redacts_env_key_by_default(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV_VAR, "env-only-key-value-42")
    assert "env-only-key-value-42" not in redact_secrets("x env-only-key-value-42 y")


@pytest.mark.parametrize(
    ("text", "leak"),
    [
        ("Authorization: Bearer abcdef123456", "abcdef123456"),
        ("using sk-proj-AbCdEf0123456789", "AbCdEf0123456789"),
        ("GET https://bob:hunter2@host/v1", "hunter2"),
        ("https://host/v1?api_key=zzz999&x=1", "zzz999"),
        ("token=abc.def.ghi", "abc.def.ghi"),
        ("password: 's3cret!'", "s3cret!"),
    ],
)
def test_redacts_common_token_shapes(text, leak):
    assert leak not in redact_secrets(text, [])


def test_redaction_keeps_ordinary_text_and_ignores_tiny_secrets():
    text = "max_tokens=100 for model m on localhost"
    assert redact_secrets(text, ["m"]) == text
    assert redact_secrets(None, []) == ""


def test_client_error_message_never_contains_key(monkeypatch):
    def boom(url, **kwargs):
        assert kwargs["headers"]["Authorization"] == f"Bearer {KEY}"
        raise requests.exceptions.ConnectionError(
            f"refused; headers={kwargs['headers']!r}"
        )

    monkeypatch.setattr(requests, "post", boom)
    client = OpenAIClient(LOCAL, KEY, "m")
    events = list(client.chat([{"role": "user", "content": "hi"}]))
    assert events[-1]["type"] == "error"
    assert KEY not in events[-1]["message"]
    assert "AI backend request failed" in events[-1]["message"]
    assert KEY not in repr(client)


# -- config persistence ----------------------------------------------------------


def test_env_api_key_is_never_written_to_config_file(monkeypatch, tmp_path):
    from sandroid.config.loader import ConfigLoader
    from sandroid.config.schema import SandroidConfig

    monkeypatch.setenv(API_KEY_ENV_VAR, KEY)
    cfg = SandroidConfig(ai={"base_url": LOCAL, "api_key": KEY, "model": "m"})
    for fmt in ("toml", "json", "yaml"):
        path = ConfigLoader().save_config(cfg, tmp_path / f"c.{fmt}", fmt)
        content = path.read_text()
        assert KEY not in content
        assert LOCAL in content


def test_config_file_key_is_still_persisted(monkeypatch, tmp_path):
    """A key the user deliberately put in the file is kept (with a warning in
    the UI) -- only env-sourced keys are stripped.
    """
    from sandroid.config.loader import ConfigLoader
    from sandroid.config.schema import SandroidConfig

    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    cfg = SandroidConfig(ai={"base_url": LOCAL, "api_key": KEY, "model": "m"})
    path = ConfigLoader().save_config(cfg, tmp_path / "c.toml", "toml")
    assert KEY in path.read_text()


# -- tool permission defaults ----------------------------------------------------

#: Every native tool that changes device/host/session state. Each must need
#: an explicit confirmation by default (never auto-run).
_STATE_CHANGING_TOOLS = {
    "clear_captured_flows",
    "clear_device_proxy",
    "create_snapshot",
    "delete_snapshot",
    "disable_app_proxy",
    "enable_adb_root",
    "enable_app_proxy",
    "inject_ca_certificate",
    "install_apk",
    "install_frida_server",
    "kill_emulator",
    "kill_process",
    "launch_app",
    "load_snapshot",
    "pull_apk",
    "pull_app_data",
    "pull_path",
    "push_ca_certificate",
    "push_path",
    "restart_emulator",
    "set_app_proxy_quic_blocking",
    "set_device_proxy",
    "set_spotlight_app",
    "spawn_privileged_subtask",
    "start_device_recording",
    "start_file_monitor",
    "start_frida_server",
    "start_mitmproxy",
    "start_replay",
    "start_screen_recording",
    "start_ssl_unpin",
    "stop_device_recording",
    "stop_file_monitor",
    "stop_frida_server",
    "stop_mitmproxy",
    "stop_screen_recording",
    "stop_ssl_unpin",
    "uninstall_apk",
}


@pytest.fixture
def empty_permission_store(monkeypatch, tmp_path):
    import sandroid.ai.tool_permissions as tp

    store = tp.ToolPermissionStore(path=tmp_path / "perms.toml")
    monkeypatch.setattr(tp, "_tool_permission_store", store)
    return store


def test_every_state_changing_tool_asks_by_default(empty_permission_store):
    import sandroid.ai
    from sandroid.ai.tool_permissions import resolve_tool_policy
    from sandroid.ai.tools.registry import RiskTier, get_tool_registry

    registry = get_tool_registry()
    registered = set(registry.names())
    assert registered >= _STATE_CHANGING_TOOLS, _STATE_CHANGING_TOOLS - registered
    for name in _STATE_CHANGING_TOOLS:
        spec = registry.get_spec(name)
        assert spec.risk != RiskTier.READ_ONLY, name
        assert resolve_tool_policy(name, spec.risk, spec.can_remember_choice) == "ask"


def test_tools_named_like_mutations_are_never_read_only():
    import sandroid.ai
    from sandroid.ai.tools.registry import RiskTier, get_tool_registry

    mutating_prefixes = (
        "start_", "stop_", "set_", "clear_", "install_", "uninstall_",
        "inject_", "push_", "kill_", "delete_", "load_", "restart_",
        "enable_", "disable_", "create_", "launch_",
    )  # fmt: skip
    registry = get_tool_registry()
    offenders = [
        name
        for name in registry.names()
        if name.startswith(mutating_prefixes)
        and registry.get_spec(name).risk == RiskTier.READ_ONLY
    ]
    assert offenders == []


def test_destructive_tools_cannot_be_remembered():
    import sandroid.ai
    from sandroid.ai.tools.registry import get_tool_registry

    registry = get_tool_registry()
    for name in (
        "clear_captured_flows",
        "delete_snapshot",
        "load_snapshot",
        "install_apk",
        "uninstall_apk",
        "inject_ca_certificate",
        "push_path",
        "spawn_privileged_subtask",
    ):
        assert registry.get_spec(name).can_remember_choice is False, name


def test_ask_without_ui_is_refused():
    """A state-changing call with no approval UI must never run."""
    import json

    import sandroid.ai
    from sandroid.ai.loop import _dispatch_one
    from sandroid.ai.tools.registry import get_tool_registry

    out = json.loads(
        _dispatch_one(get_tool_registry(), "uninstall_apk", {"package": "x.y"})
    )
    assert "needs confirmation" in out["error"]


# -- experimental labels ---------------------------------------------------------


def test_bypass_categories_are_labelled_experimental_and_off_by_default():
    from sandroid.analysis.detection_bypass import BypassService

    svc = BypassService()
    assert svc.armed_categories() == []
    assert svc.active_categories() == []
    for category in svc.categories():
        assert "experimental" in svc.display_name(category).lower()
        manager_cls = svc._manager_class(category)
        assert "experimental" in manager_cls.DISPLAY_NAME.lower()


def test_ssl_unpin_ai_tool_is_marked_experimental():
    import sandroid.ai
    from sandroid.ai.tools.registry import get_tool_registry

    spec = get_tool_registry().get_spec("start_ssl_unpin")
    assert "EXPERIMENTAL" in spec.description


def test_safety_module_has_no_import_time_dependency_on_mcp():
    assert "mcp" not in safety.__dict__
