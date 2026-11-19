"""The AI chat dock under the lens (``MainScreen`` + ``ChatDock``, §6).

Ctrl+Y focus semantics, the Esc order, Shift+Up/Down presets and clamps,
max (chosen, and the effective max of a short window), border drag and
double-click, ``-narrow``, the log drawer cap, persistence (mocked) and
the one ChatPanel that never unmounts. No device.
"""

from __future__ import annotations

import pytest
from pilot_helpers import boot, settle, until

from sandroid.tui.screens.main_screen import (
    CHAT_PRESETS,
    ChatDock,
    MainScreen,
    chat_rows,
    snap_chat_ratio,
)
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown

SIZE = (160, 45)


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


@pytest.fixture(autouse=True)
def _private_config_home(tmp_path, monkeypatch):
    """Each test gets its own config dir (the UI-state file lives there)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def saved(monkeypatch):
    """Record ``tui.chat_dock`` writes instead of touching the config file."""
    calls: list[tuple[float, bool]] = []
    monkeypatch.setattr(
        MainScreen,
        "_write_chat_dock_prefs",
        lambda self, ratio, maximized: calls.append((ratio, maximized)),
    )
    return calls


def _dock(ms) -> ChatDock:
    return ms.query_one("#chat-dock", ChatDock)


def _rows(ms) -> int:
    return _dock(ms).outer_size.height


def _left_h(ms) -> int:
    return ms.query_one("#left-col").size.height


def _content() -> InspectorContent:
    return InspectorContent(title="row", sections=[("Summary", "x")], key="k")


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------


def test_chat_rows_clamp_and_snap() -> None:
    assert chat_rows(40, 0.5) == 20
    assert chat_rows(40, 0.3) == 12
    assert chat_rows(19, 0.3) == 10  # at least 10 chat rows
    assert chat_rows(19, 0.7) == 13  # at least 6 lens rows
    assert chat_rows(16, 0.7) == 10
    assert [snap_chat_ratio(r) for r in (0.0, 0.41, 0.6, 0.66, 1.0)] == [
        0.3,
        0.5,
        0.5,
        0.7,
        0.7,
    ]
    assert CHAT_PRESETS == (0.3, 0.5, 0.7)


def test_toggle_chat_is_a_palette_and_keymap_action() -> None:
    from sandroid.core.menu_controller import ActionCategory, MenuController
    from sandroid.tui.app import SandroidTUI

    MenuController.reset()
    action = MenuController.get().get_action_by_name("toggle_chat")
    assert action is not None
    assert action.category is ActionCategory.NAVIGATION
    assert action.key == "ctrl+y"
    assert action.inline_text == "[^Y] AI chat"
    ids = {b.id: b.key for b in SandroidTUI.BINDINGS if b.id}
    assert ids["toggle_chat"] == "ctrl+y"


def test_config_snaps_the_saved_ratio() -> None:
    from sandroid.config.schema import ChatDockConfig, TUIConfig

    assert TUIConfig().chat_dock.ratio == 0.5
    assert TUIConfig().chat_dock.maximized is False
    assert ChatDockConfig(ratio=0.62).ratio == 0.7


# --------------------------------------------------------------------------
# open / focus / close
# --------------------------------------------------------------------------


async def test_ctrl_y_opens_focuses_and_closes(saved) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dock = _dock(ms)
        panel = ms.query_one("#chat-panel")
        assert ms.chat_mode == "closed"
        assert not dock.display
        assert ms.query_one("#log-ticker-hint").render().plain == "^Y AI · ` log"

        await pilot.press("ctrl+y")
        await settle(pilot)
        assert ms.chat_mode == "split"
        assert is_shown(dock)
        assert is_shown(ms.query_one("#lens-host"))
        assert app.focused.id == "chat-input"
        assert ms.chat_has_focus
        assert ms.has_class("-chat-open")
        assert dock.border_title == "▚▄▄▞ Sandroid AI"
        assert dock.border_subtitle == "50% · ⇧↑↓ size · ^Y close"
        assert _rows(ms) == chat_rows(_left_h(ms), 0.5)

        # Focus elsewhere: Ctrl+Y focuses the chat, it does not close it.
        ms.lens_widget().focus()
        await settle(pilot)
        assert not ms.chat_has_focus
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert ms.chat_is_open
        assert app.focused.id == "chat-input"

        await pilot.press("ctrl+y")
        await settle(pilot)
        assert ms.chat_mode == "closed"
        assert not dock.display
        assert ms.lens_widget() in app.focused.ancestors_with_self
        assert ms.query_one("#chat-panel") is panel
        assert saved == []  # opening / closing persists nothing


async def test_banner_is_visible_on_first_open() -> None:
    app = _app()
    async with app.run_test(size=(80, 24)) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        log = ms.query_one("#chat-log")
        await until(pilot, lambda: log.scroll_y == 0 and log.size.height > 0)
        await pilot.pause(0.3)
        assert log.scroll_y == 0


async def test_esc_order_dock_inspector_drawer_chat() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        ms.toggle_log_drawer()
        ms.open_inspector(_content())
        await settle(pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        # The Inspector and the chat coexist.
        assert ms.inspector_is_open
        assert ms.chat_is_open
        assert is_shown(ms.query_one("#inspector"))
        assert is_shown(_dock(ms))
        assert app.focused.id == "chat-input"

        await pilot.press("escape")  # 1. dock focus -> lens, chat stays
        await settle(pilot)
        assert ms.chat_is_open
        assert not ms.chat_has_focus
        assert ms.lens_widget() in app.focused.ancestors_with_self
        await pilot.press("escape")  # 2. Inspector
        await settle(pilot)
        assert not ms.inspector_is_open
        assert ms.chat_is_open
        await pilot.press("escape")  # 3. log drawer
        await settle(pilot)
        assert not ms.log_drawer_is_open
        assert ms.chat_is_open
        await pilot.press("escape")  # 4. chat
        await settle(pilot)
        assert not ms.chat_is_open


async def test_esc_answers_a_focused_approval_prompt_first() -> None:
    from sandroid.ai.tools.registry import RiskTier, ToolSpec
    from sandroid.tui.widgets.tool_permission_prompt import ToolPermissionPrompt

    spec = ToolSpec(
        name="kill_app",
        description="Kill an app.",
        parameters={"type": "object", "properties": {}, "required": []},
        func=lambda: None,
        risk=RiskTier.REVERSIBLE,
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        prompt = ToolPermissionPrompt(spec, {}, input_grace_s=0)
        cancelled: list[bool] = []
        prompt.action_cancel = lambda: cancelled.append(True)  # type: ignore[method-assign]
        await ms.query_one("#chat-panel").mount(prompt)
        prompt.focus()
        await settle(pilot)
        await pilot.press("escape")
        await settle(pilot)
        assert cancelled == [True]
        assert ms.chat_is_open
        assert ms.chat_has_focus


# --------------------------------------------------------------------------
# sizes
# --------------------------------------------------------------------------


async def test_shift_arrows_step_presets_and_max(saved) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        # Closed: Shift+Up does nothing (the binding is disabled).
        assert ms.check_action("chat_size", (1,)) is False
        await pilot.press("shift+up")
        await settle(pilot)
        assert ms.chat_mode == "closed"
        assert saved == []

        await pilot.press("ctrl+y")
        await settle(pilot)
        h = _left_h(ms)
        assert h == 40
        assert _rows(ms) == 20
        await pilot.press("shift+up")
        await settle(pilot)
        assert (ms.chat_mode, ms.chat_ratio, _rows(ms)) == ("split", 0.7, 28)
        assert _dock(ms).styles.inline.has_rule("height")
        await pilot.press("shift+up")
        await settle(pilot)
        assert ms.chat_mode == "max"
        assert ms.chat_is_maximized
        # Max clears the inline split height: the dock fills the column.
        assert not _dock(ms).styles.inline.has_rule("height")
        assert _rows(ms) == h
        assert not is_shown(ms.query_one("#lens-host"))
        assert _dock(ms).border_subtitle == "max · ⇧↓ restore · ^Y close"
        await pilot.press("shift+up")  # already max
        await settle(pilot)
        assert ms.chat_mode == "max"
        await pilot.press("shift+down")
        await settle(pilot)
        assert (ms.chat_mode, ms.chat_ratio, _rows(ms)) == ("split", 0.7, 28)
        assert is_shown(ms.query_one("#lens-host"))
        for _ in range(4):  # 0.5, 0.3, then stays at 0.3
            await pilot.press("shift+down")
        await settle(pilot)
        assert (ms.chat_ratio, _rows(ms)) == (0.3, 12)
        await until(pilot, lambda: len(saved) >= 5)
        assert saved == [
            (0.7, False),
            (0.7, True),
            (0.7, False),
            (0.5, False),
            (0.3, False),
        ]
        assert ms.chat_is_open
        assert app.focused.id == "chat-input"


async def test_clamps_at_80x24() -> None:
    app = _app()
    async with app.run_test(size=(80, 24)) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        h = _left_h(ms)
        assert h >= 16
        assert not ms.chat_is_maximized
        ms.action_chat_size(-1)  # 0.3
        await settle(pilot)
        assert _rows(ms) == 10  # min chat rows
        ms.action_chat_size(1)
        ms.action_chat_size(1)  # 0.7
        await settle(pilot)
        assert _rows(ms) == min(round(h * 0.7), h - 6)
        assert ms.query_one("#lens-host").outer_size.height >= 6


async def test_short_window_shows_the_chat_maximized() -> None:
    """80x24 with the log drawer open: < 16 rows left -> effective max."""
    app = _app()
    async with app.run_test(size=(80, 24)) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert not ms.chat_is_maximized
        assert _dock(ms).styles.inline.has_rule("height")
        ms.toggle_log_drawer()
        await settle(pilot)
        # The drawer may take at most 30% while the chat is open.
        assert ms.query_one("#log-drawer").outer_size.height <= round(24 * 0.3)
        assert _left_h(ms) < 16
        await until(pilot, lambda: ms.chat_is_maximized)
        assert ms.chat_mode == "split"  # the choice is kept
        assert not _dock(ms).styles.inline.has_rule("height")
        assert not is_shown(ms.query_one("#lens-host"))
        assert _rows(ms) == _left_h(ms)
        assert _dock(ms).border_subtitle == "small window · ^Y close"
        assert not ms.chat_can_resize
        # Closing the drawer gives the split back.
        ms.toggle_log_drawer()
        await settle(pilot)
        await until(pilot, lambda: not ms.chat_is_maximized)
        assert is_shown(ms.query_one("#lens-host"))


async def test_lens_switch_leaves_max() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        ms.toggle_chat_max()
        await settle(pilot)
        assert ms.chat_mode == "max"
        ms.switch_lens("network")
        await settle(pilot)
        assert ms.chat_mode == "split"
        assert is_shown(ms.query_one("#network-panel"))
        assert is_shown(_dock(ms))


async def test_esc_from_max_restores_the_split_and_focuses_the_lens() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        ms.toggle_chat_max()
        await settle(pilot)
        await pilot.press("escape")
        await settle(pilot)
        assert ms.chat_mode == "split"
        assert ms.lens_widget() in app.focused.ancestors_with_self


async def test_drag_border_resizes_and_snaps(saved) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        col = ms.query_one("#left-col")
        bottom = col.content_region.bottom
        top = _dock(ms).region.y
        assert bottom - top == 20
        await pilot.mouse_down("#chat-dock", offset=(10, 0))
        await pilot.hover("#chat-dock", offset=(10, -6))  # 26 rows: live
        await settle(pilot)
        assert _rows(ms) == 26
        assert "release to snap" in _dock(ms).border_subtitle
        await pilot.mouse_up("#chat-dock", offset=(10, 0))
        await settle(pilot)
        assert (ms.chat_mode, ms.chat_ratio, _rows(ms)) == ("split", 0.7, 28)
        await until(pilot, lambda: saved == [(0.7, False)])

        # Dragged nearly to the top: snaps to max.
        await pilot.mouse_down("#chat-dock", offset=(10, 0))
        await pilot.hover("#lens-host", offset=(10, 1))
        await pilot.mouse_up("#chat-dock", offset=(10, 0))
        await settle(pilot)
        assert ms.chat_mode == "max"

        # Double-click on the border toggles max.
        await pilot.double_click("#chat-dock", offset=(10, 0))
        await settle(pilot)
        assert ms.chat_mode == "split"
        await pilot.double_click("#chat-dock", offset=(10, 0))
        await settle(pilot)
        assert ms.chat_mode == "max"


async def test_narrow_class_and_inspector_width() -> None:
    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        ms = await boot(app, pilot)
        assert ms.has_class("-narrow")
        ms.open_inspector(_content())
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert ms.query_one("#side-slot").outer_size.width == 45
        assert ms.query_one("#left-col").size.width == 55
        await pilot.resize_terminal(160, 45)
        await until(pilot, lambda: not ms.has_class("-narrow"))
        await settle(pilot)
        assert ms.query_one("#side-slot").outer_size.width == 64


async def test_saved_size_is_used_and_chat_starts_closed(saved) -> None:
    from sandroid.config.schema import ChatDockConfig

    app = _app()
    app._sandroid_config.tui.chat_dock = ChatDockConfig(ratio=0.3, maximized=True)
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        assert ms.chat_mode == "closed"
        assert ms.chat_ratio == 0.3
        panel = ms.query_one("#chat-panel")
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert ms.chat_mode == "max"
        await pilot.press("shift+down")
        await settle(pilot)
        assert (ms.chat_ratio, _rows(ms)) == (0.3, 12)
        # The same ChatPanel object across every mode.
        await pilot.press("ctrl+y")  # close
        await pilot.press("ctrl+y")  # reopen: split now (max was undone)
        await settle(pilot)
        assert ms.chat_mode == "split"
        assert ms.query_one("#chat-panel") is panel
        assert panel.is_attached
        await until(pilot, lambda: saved == [(0.3, False)])


async def test_saved_size_goes_to_the_ui_state_file_not_the_config(
    tmp_path, monkeypatch
) -> None:
    """Unmocked: the size lands in ``tui_state.json`` (0600); a project
    ``sandroid.toml`` with an API key is left byte-for-byte alone (it used to
    become a dump of the whole merged config, key included).
    """
    import json
    import stat

    from sandroid.config.ui_state import ui_state_path

    project = tmp_path / "project"
    project.mkdir()
    toml = project / "sandroid.toml"
    original = '[ai]\napi_key = "sk-secret-123"\nmodel = "m"\n'
    toml.write_text(original)
    toml.chmod(0o644)
    monkeypatch.chdir(project)
    monkeypatch.setenv("SANDROID_AI__API_KEY", "sk-env-456")
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await pilot.press("shift+down")
        await settle(pilot)
        path = ui_state_path()
        await until(pilot, path.exists)
        await until(
            pilot,
            lambda: json.loads(path.read_text()).get("chat_dock", {}).get("ratio")
            == 0.3,
        )
        assert ms.chat_ratio == 0.3
    assert toml.read_text() == original
    assert stat.S_IMODE(toml.stat().st_mode) == 0o644
    state = path.read_text()
    assert "sk-" not in state
    assert json.loads(state) == {"chat_dock": {"ratio": 0.3, "maximized": False}}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # The next run picks it up.
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        assert ms.chat_ratio == 0.3


async def test_dock_frame_follows_every_theme() -> None:
    """Every theme's stylesheet loads with the chat open; the frame uses the
    theme's ``$lens-*`` tokens (no hard-coded #chat-dock rule is left).
    """
    from sandroid.tui.themes import THEMES, get_theme_css_path

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        dock = _dock(ms)
        for name, theme in THEMES.items():
            app._apply_theme(theme, get_theme_css_path(name))
            await settle(pilot)
            assert app.theme == f"sandroid-{name}"
            assert app.theme_variables["chat-tool"].upper() == theme.tool_color.upper()
            # Focused (the chat input): $lens-rule-focus.
            color = dock.styles.border_top[1].hex.upper()
            assert color == theme.lens.rule_focus.upper(), name
            ms.lens_widget().focus()
            await settle(pilot)
            assert dock.styles.border_top[1].hex.upper() == theme.lens.rule.upper()
            assert (
                dock.styles.border_title_color.hex.upper() == theme.lens.accent.upper()
            )
            await pilot.press("ctrl+y")
            await settle(pilot)


# --------------------------------------------------------------------------
# approvals arriving while the analyst works elsewhere
# --------------------------------------------------------------------------


def _approval(tmp_path, monkeypatch):
    """A pending approval and the event that announces it."""
    import time

    import sandroid.ai.tool_permissions as perms
    from sandroid.ai.loop import AgentEvent
    from sandroid.ai.tool_permissions import ToolPermissionStore
    from sandroid.ai.tools.registry import RiskTier
    from sandroid.tui.widgets.chat_panel import ChatPanel

    monkeypatch.setattr(
        perms, "_tool_permission_store", ToolPermissionStore(path=tmp_path / "p.toml")
    )
    monkeypatch.setattr(ChatPanel, "APPROVAL_INPUT_GRACE_S", 0.0)
    pending = perms.get_approval_broker().submit(
        agent_id="a-re-1",
        agent_label="researcher a-re-1",
        tool="kill_app",
        args={"package": "com.x"},
        risk=RiskTier.CONSEQUENTIAL,
    )
    event = AgentEvent(
        "approval_request",
        "a-re-1",
        None,
        "t-1",
        "",
        0,
        time.time(),
        {"request_id": pending.request.request_id, "tool": "kill_app"},
    )
    return pending, event


async def test_approval_in_a_closed_dock_shows_without_stealing_focus(
    tmp_path, monkeypatch
) -> None:
    """Verifier repro: the card focused itself in the hidden dock and the
    next Enter (meant for the lens) approved it.
    """
    pending, event = _approval(tmp_path, monkeypatch)
    app = _app()
    toasts: list[str] = []
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        monkeypatch.setattr(app, "notify", lambda message, **kw: toasts.append(message))
        ms._chat_max_pref = True  # last chosen "max": must still open split
        ms.lens_widget().focus()
        await settle(pilot)
        lens_focus = app.focused
        assert not ms.chat_is_open
        panel = ms.query_one("#chat-panel")
        panel._sink(event)
        await until(pilot, lambda: panel.pending_prompt() is not None)
        await settle(pilot)
        prompt = panel.pending_prompt()
        assert ms.chat_is_open  # opened, so the card is visible
        assert ms.chat_mode == "split"  # the lens with the focus stays visible
        assert app.focused is lens_focus
        assert not ms.chat_has_focus
        assert toasts
        assert "Ctrl+Y" in toasts[0]
        ticker = ms.query_one("#log-ticker")
        assert ticker.attention
        assert "approval" in ticker.attention
        await pilot.press("enter")
        await settle(pilot)
        assert not pending.done
        # Ctrl+Y goes to the card (not just the input); then 1 = Yes.
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert prompt.has_focus
        await pilot.press("1")
        await until(pilot, lambda: pending.done)
        assert pending.decision.choice == "once"
        await until(pilot, lambda: not ticker.attention)


async def test_approval_while_typing_in_the_chat_swallows_stray_letters(
    tmp_path, monkeypatch
) -> None:
    """Verifier repro: the card took the focus from the input and the rest of
    the typed word ran App hotkeys (``s`` = screenshot).
    """
    from sandroid.tui.app import SandroidTUI

    pending, event = _approval(tmp_path, monkeypatch)
    calls: list[str] = []
    monkeypatch.setattr(
        SandroidTUI, "action_screenshot", lambda self: calls.append("screenshot")
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await pilot.press("ctrl+y")
        await settle(pilot)
        assert app.focused.id == "chat-input"
        panel = ms.query_one("#chat-panel")
        panel._sink(event)
        await until(pilot, lambda: panel.pending_prompt() is not None)
        prompt = panel.pending_prompt()
        await until(pilot, lambda: prompt.has_focus)
        await pilot.press("s", "a", "q")
        await settle(pilot)
        assert calls == []
        assert not pending.done
        assert ms.chat_is_open
        await pilot.press("escape")  # Esc = No
        await until(pilot, lambda: pending.done)
        assert pending.decision.choice == "no"
