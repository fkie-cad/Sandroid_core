"""Schema-level tests for the AIConfig chat-behavior toggles.

The connection fields (base_url/api_key/model) intentionally have no
defaults -- see AIConfig's docstring. These two behavior toggles do, since
they're just chat-UI presentation preferences read by ChatPanel.
"""

from pathlib import Path

from sandroid.config.schema import AIConfig


def test_show_verbose_thinking_defaults_to_false():
    """Raw reasoning/thinking text must be opt-in, not dumped by default."""
    assert AIConfig().show_verbose_thinking is False


def test_show_chat_mascot_defaults_to_true():
    """The mascot is a low-risk showcase touch -- on unless turned off."""
    assert AIConfig().show_chat_mascot is True


def test_data_share_path_defaults_to_ai_share_under_home():
    """The AI's file tools need an always-available anchor directory."""
    assert AIConfig().data_share_path == Path("~/Sandroid/ai_share/").expanduser()


def test_data_share_path_expands_tilde():
    """A user-supplied ~-relative path must be expanded to an absolute one."""
    config = AIConfig(data_share_path="~/custom_ai_share/")
    assert config.data_share_path == Path("~/custom_ai_share/").expanduser()
    assert config.data_share_path.is_absolute()


def test_extra_host_paths_defaults_to_empty_list():
    """No additional host roots are exposed to the AI by default."""
    assert AIConfig().extra_host_paths == []


def test_extra_host_paths_expands_tilde_for_each_item():
    """Each configured extra root must be independently ~-expanded."""
    config = AIConfig(extra_host_paths=["~/foo", "~/bar/baz"])
    assert config.extra_host_paths == [
        Path("~/foo").expanduser(),
        Path("~/bar/baz").expanduser(),
    ]


# -- AI foundations fields (transport, budgets, context, agents) ----------------


def test_transport_fields_default_to_server_defaults():
    cfg = AIConfig()
    assert cfg.profile is None
    assert cfg.profile_overrides == {}
    assert cfg.context_window is None
    assert cfg.max_tokens is None
    assert cfg.temperature is None
    assert cfg.top_p is None
    assert cfg.tool_choice is None
    assert cfg.extra_body == {}
    assert cfg.request_timeout == (10.0, 120.0)
    assert cfg.retry_max == 4


def test_budget_context_agent_defaults():
    cfg = AIConfig()
    assert cfg.budgets.chat_max_rounds == 25
    assert cfg.budgets.agent_max_rounds == 20
    assert cfg.budgets.chat_max_tokens > 0
    assert cfg.budgets.chat_max_wall_s > 0
    ctx = cfg.context
    assert ctx.result_cap_tokens == 8000
    assert ctx.turn_result_budget_tokens == 25_000
    assert ctx.mask_at == 0.50
    assert ctx.keep_recent_results == 10
    assert ctx.summarize_at == 0.85
    assert ctx.summary_keep_tokens == 40_000
    assert ctx.output_reserve_tokens == 32_000
    agents = cfg.agents
    assert agents.gateway_concurrency == 4
    assert agents.researcher_max == 3
    assert agents.operator_max == 1
    assert agents.max_auto_wakes == 3


def test_nested_sections_accept_partial_dicts():
    cfg = AIConfig(context={"mask_at": 0.6}, budgets={"chat_max_rounds": 40})
    assert cfg.context.mask_at == 0.6
    assert cfg.context.summarize_at == 0.85
    assert cfg.budgets.chat_max_rounds == 40
    assert cfg.budgets.agent_max_rounds == 20


def test_invalid_ai_values_are_rejected():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AIConfig(context={"mask_at": 0.9, "summarize_at": 0.85})
    with pytest.raises(ValidationError):
        AIConfig(request_timeout=(0, 120))
    with pytest.raises(ValidationError):
        AIConfig(tool_choice="always")


def test_chat_mascot_and_legacy_alias():
    assert AIConfig().chat_mascot == "auto"
    assert AIConfig().mascot_style == "auto"
    assert AIConfig(chat_mascot="ascii").mascot_style == "ascii"
    assert AIConfig(chat_mascot="off").mascot_style == "off"
    # Legacy switch: false hides the mascot whatever chat_mascot says.
    assert AIConfig(show_chat_mascot=False).mascot_style == "off"
    assert AIConfig(show_chat_mascot=False, chat_mascot="blocks").mascot_style == (
        "off"
    )
    # Neither field is rewritten, so the Settings switch can turn it back on.
    cfg = AIConfig(show_chat_mascot=False)
    cfg.show_chat_mascot = True
    assert cfg.mascot_style == "auto"


def test_timeline_has_ai_source_on_by_default():
    from sandroid.config.schema import TimelineConfig

    assert TimelineConfig().sources["ai"] is True


def test_default_toml_still_validates_with_ai_sections():
    import tomllib

    from sandroid.config.schema import SandroidConfig

    default = Path(__file__).resolve().parents[2] / "src/sandroid/config/default.toml"
    with default.open("rb") as fh:
        cfg = SandroidConfig(**tomllib.load(fh))
    assert cfg.timeline.sources["ai"] is True
    assert cfg.ai.context.mask_at == 0.50
