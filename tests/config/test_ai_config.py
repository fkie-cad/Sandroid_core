"""Schema-level tests for the AIConfig chat-behavior toggles.

The connection fields (base_url/api_key/model) intentionally have no
defaults -- see AIConfig's docstring. These two behavior toggles do, since
they're just chat-UI presentation preferences read by ChatPanel.
"""

from sandroid.config.schema import AIConfig


def test_show_verbose_thinking_defaults_to_false():
    """Raw reasoning/thinking text must be opt-in, not dumped by default."""
    assert AIConfig().show_verbose_thinking is False


def test_show_chat_mascot_defaults_to_true():
    """The mascot is a low-risk showcase touch -- on unless turned off."""
    assert AIConfig().show_chat_mascot is True
