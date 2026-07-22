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
