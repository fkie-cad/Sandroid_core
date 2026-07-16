"""Tests for two real bugs found in the Settings screen's AI Chat tab.

Uses the same ``App.run_test()`` headless harness as ``test_chat_panel.py``
(see that file's module docstring for why this is the right tool here).
"""

from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Static, Switch

from sandroid.config import SandroidConfig
from sandroid.core.toolbox import Toolbox
from sandroid.tui.screens.settings_screen import SettingsScreen
from sandroid.tui.widgets.chat_panel import ChatPanel


class _SettingsHarness(App):
    """Host app mirroring the real shape: a base screen holding ChatPanel
    (standing in for MainScreen), with SettingsScreen pushed on top as a
    modal -- exactly the screen_stack shape ``SettingsScreen._refresh_chat_panel``
    has to walk in production (ChatPanel is *not* on the active/top screen).
    """

    def __init__(self) -> None:
        super().__init__()
        # Mirrors SandroidTUI.sandroid_config -- SettingsScreen._get_config()
        # prefers this over get_config()'s file-backed singleton, so the
        # tab's *displayed* values are deterministic regardless of any real
        # config file on the test machine.
        self.sandroid_config = SandroidConfig()

    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat-panel")


# -- Bug A: cramped/misaligned AI Chat tab layout ---------------------------


@pytest.mark.smoke
async def test_ai_chat_help_text_spans_full_row_with_gap_before_next_row():
    """Regression test for the reported layout bug: the help-text ``Static``
    following "Show Verbose Thinking:" used to reuse ``.setting-label``
    (``width: 30``, right-aligned, no margin) -- the class meant for short
    row labels, not wrapped paragraphs. That squeezed the paragraph into a
    narrow right-aligned column tall enough (7 wrapped lines) to butt
    directly against "Show Chat Mascot:" with zero gap. The fix is a
    dedicated ``.setting-help`` class: full row width (so it wraps like a
    normal paragraph, not a cramped column) and its own margin-bottom (so a
    visible gap always separates it from the next row).
    """
    app = _SettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()
        screen.query_one("#settings-tabs").active = "tab-ai-chat"
        await pilot.pause()

        pane = screen.query_one("#tab-ai-chat")
        rows = pane.query(".setting-row")
        statics = [w for w in pane.walk_children() if isinstance(w, Static)]
        help_texts = [w for w in statics if "setting-help" in w.classes]

        assert len(rows) == 2
        assert len(help_texts) == 2

        verbose_row, mascot_row = rows[0], rows[1]
        thinking_help = help_texts[0]

        # Full row width, not the narrow 30-column label width.
        assert thinking_help.region.width == verbose_row.region.width

        # A real gap: the help text's bottom edge must sit strictly above
        # the next row's top edge (the old bug had them touch exactly, 0
        # rows apart).
        gap = mascot_row.region.y - thinking_help.region.bottom
        assert gap >= 1, f"expected a visible gap, got {gap} rows"


# -- Bug B: AI Chat toggles don't take effect immediately -------------------


@pytest.mark.smoke
async def test_toggle_show_chat_mascot_immediately_hides_live_mascot(monkeypatch):
    """Core regression test: flipping "Show Chat Mascot" off must hide the
    mascot on an already-mounted, idle ``ChatPanel`` immediately -- with NO
    other event (chat turn, header refresh, etc.) happening in between.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _SettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)
        assert mascot.display is True  # sanity: visible before any toggle

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        assert switch.value is True

        switch.toggle()  # the ONLY thing that happens -- no chat activity
        await pilot.pause()

        # The live config object ChatPanel actually reads was updated...
        assert ai_cfg.show_chat_mascot is False
        # ...and the already-mounted ChatPanel repainted without being told
        # about it any other way.
        assert mascot.display is False


@pytest.mark.smoke
async def test_toggle_show_chat_mascot_back_on_immediately_shows_it(monkeypatch):
    """Symmetric case: toggling back on must re-show the mascot immediately."""
    ai_cfg = SimpleNamespace(show_chat_mascot=False, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _SettingsHarness()
    # The Switch's *displayed* value comes from the settings screen's own
    # config (self.app.sandroid_config), a separate object from Toolbox.config
    # on purpose (that's the crux of the bug) -- match it here so the switch
    # actually starts unchecked, matching ai_cfg's starting state.
    app.sandroid_config.ai.show_chat_mascot = False
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)
        assert mascot.display is False

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        assert switch.value is False

        switch.toggle()
        await pilot.pause()

        assert ai_cfg.show_chat_mascot is True
        assert mascot.display is True


async def test_toggle_show_verbose_thinking_applies_to_live_config_immediately(
    monkeypatch,
):
    """``show_verbose_thinking`` has no on-screen content that needs a
    retroactive repaint (confirmed by reading ``chat_panel.py``: it's only
    read once, at the moment a reasoning phase ends via
    ``_finalize_reasoning_only``) -- but the live config write itself must
    still happen immediately, not wait for Save, so the very next reasoning
    phase already honors the new value.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _SettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_verbose_thinking", Switch)
        switch.toggle()
        await pilot.pause()

        assert ai_cfg.show_verbose_thinking is True


@pytest.mark.smoke
async def test_cancel_reverts_live_mascot_toggle_preview(monkeypatch):
    """Mirrors the theme radio's preview/revert-on-cancel contract: a switch
    applied live for preview but never saved must not silently stick.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _SettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        switch.toggle()
        await pilot.pause()
        assert ai_cfg.show_chat_mascot is False
        assert mascot.display is False

        screen.action_cancel()
        await pilot.pause()

        assert ai_cfg.show_chat_mascot is True
        assert mascot.display is True


def test_on_switch_changed_still_stages_into_pending():
    """Non-regression: the live-apply path must not replace the existing
    stage-into-_pending behavior Save relies on for persistence.
    """
    from textual.widgets import Switch as SwitchWidget

    screen = SettingsScreen()
    switch = SwitchWidget(value=False, id="setting-ai--show_chat_mascot")
    event = SwitchWidget.Changed(switch, False)
    screen.on_switch_changed(event)

    assert screen._pending == {"ai.show_chat_mascot": False}
