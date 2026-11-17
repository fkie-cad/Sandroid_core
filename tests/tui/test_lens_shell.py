"""Lens shell (phase A): lenses, Inspector, side slot, log drawer, scope.

Drives the full ``SandroidTUI`` through Textual's pilot; the suite-wide
conftest blocks every device access, so "no device connected" is the
natural state.
"""

from __future__ import annotations

import pytest

from sandroid.tui.widgets.lens_shell import (
    LENSES,
    InspectorContent,
    is_shown,
)

SIZE = (160, 45)


async def _settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause(0.05)


async def _boot(app, pilot) -> None:
    await _settle(pilot, 8)
    if type(app.screen).__name__ != "MainScreen":
        await pilot.press("enter")  # first-run welcome modal
        await _settle(pilot, 4)
    assert type(app.screen).__name__ == "MainScreen"


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _content(title="row", key="k1") -> InspectorContent:
    return InspectorContent(
        title=title,
        subtitle="POST example.org/a",
        sections=[("Summary", "[b]hello[/b]"), ("Raw", "x=1")],
        footer="m mark",
        key=key,
    )


# --------------------------------------------------------------------------
# lenses
# --------------------------------------------------------------------------


async def test_digits_switch_lenses_and_focus_them() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        assert ms.active_lens == "app"
        for spec in reversed(LENSES):
            await pilot.press(spec.key)
            await _settle(pilot)
            assert ms.active_lens == spec.id
            body = ms.lens_widget(spec.id)
            assert body.id == spec.widget_id
            assert is_shown(body)
            assert app.focused is not None
            assert body in app.focused.ancestors_with_self
            tab = ms.query_one(f"#lens-tab-{spec.id}")
            assert tab.has_class("-active")
        # No Snapshots tab any more; Diffs left Files for the Runs lens.
        assert not ms.query("#snapshots-panel")
        assert not ms.query("#files-diffs")
        assert ms.query_one("#runs-panel").__class__.__name__ == "DiffsView"


async def test_shift_arrows_cycle_lenses() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        seen = []
        for _ in range(len(LENSES)):
            await pilot.press("shift+right")
            await _settle(pilot)
            seen.append(ms.active_lens)
        assert seen == ["network", "files", "runs", "app"]
        await pilot.press("shift+left")
        await _settle(pilot)
        assert ms.active_lens == "runs"


async def test_digits_do_nothing_while_a_modal_is_open() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("question_mark")
        await _settle(pilot)
        assert type(app.screen).__name__ == "HelpScreen"
        app.action_switch_lens("runs")
        await _settle(pilot)
        assert ms.active_lens == "app"
        await pilot.press("escape")


async def test_legacy_navigation_helpers_redirect() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        ms.open_files_tab("files-diffs")
        await _settle(pilot)
        assert ms.active_lens == "runs"
        ms.open_files_tab("files-watchlist")
        await _settle(pilot)
        assert ms.active_lens == "files"
        assert ms.lens_widget() in app.focused.ancestors_with_self
        ms.open_fritap_tab()
        await _settle(pilot)
        assert ms.active_lens == "network"
        assert ms.query_one("#network-body").current == "fritap-panel"
        ms.cycle_bottom_tab(1)
        await _settle(pilot)
        assert ms.active_lens == "files"


async def test_lens_badge_and_caption() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        ms.set_lens_badge("network", "⚑2")
        ms.set_lens_caption("network", "flows", "10 of 247")
        await _settle(pilot)
        assert "⚑2" in str(ms.query_one("#lens-tab-network").render())
        host = ms.query_one("#lens-host")
        assert host.border_title == ""  # app lens: no caption set
        await pilot.press("2")
        await _settle(pilot)
        assert host.border_title == "Network · flows"
        assert host.border_subtitle == "10 of 247"
        ms.set_lens_badge("network", None)
        await _settle(pilot)
        assert "⚑" not in str(ms.query_one("#lens-tab-network").render())


async def test_lens_activation_hook_is_called(monkeypatch) -> None:
    from sandroid.tui.widgets.diffs_view import DiffsView

    calls = []
    monkeypatch.setattr(
        DiffsView, "on_lens_activated", lambda self: calls.append(1), raising=False
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("4")
        await _settle(pilot)
        assert calls == [1]


# --------------------------------------------------------------------------
# log drawer + ticker
# --------------------------------------------------------------------------


async def test_backtick_toggles_drawer_and_ticker_mirrors_log() -> None:
    from sandroid.tui.widgets import ActivityLog

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        log = ms.query_one("#activity-log", ActivityLog)
        assert not is_shown(log)
        log.log_info("hello from the ticker test")
        await _settle(pilot)
        ticker = ms.query_one("#log-ticker")
        assert "hello from the ticker test" in ticker.last_line
        # Blank / separator lines never replace the ticker text.
        log.write("")
        log.write("[dim]────────[/dim]")
        await _settle(pilot)
        assert "hello from the ticker test" in ticker.last_line

        await pilot.press("grave_accent")
        await _settle(pilot)
        assert ms.log_drawer_is_open
        assert is_shown(log)
        await pilot.press("grave_accent")
        await _settle(pilot)
        assert not ms.log_drawer_is_open

        # Esc closes an open drawer too.
        ms.toggle_log_drawer()
        await _settle(pilot)
        await pilot.press("escape")
        await _settle(pilot)
        assert not ms.log_drawer_is_open


# --------------------------------------------------------------------------
# inspector / side slot
# --------------------------------------------------------------------------


async def test_inspector_open_update_close_and_esc_precedence(monkeypatch) -> None:
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        quits = []
        monkeypatch.setattr(
            app._quit_controller, "request_quit", lambda: quits.append(1)
        )
        ms.open_inspector(_content())
        await _settle(pilot)
        assert ms.inspector_is_open
        inspector = ms.query_one("#inspector")
        assert is_shown(inspector)
        assert inspector.border_title == "Inspector · row"
        assert ms.inspector_content.key == "k1"
        assert ms.inspector_content.lens == "app"
        # Focus stays in the lens.
        assert ms.lens_widget() in app.focused.ancestors_with_self

        ms.update_inspector(_content(title="row v2"))
        await _settle(pilot)
        assert inspector.border_title == "Inspector · row v2"

        app._notifications.clear()
        await pilot.press("escape")
        await _settle(pilot)
        assert not ms.inspector_is_open
        assert quits == []
        # Nothing was open, so this Esc only produced the hint, not a quit.
        assert not [n for n in app._notifications if "q to quit" in n.message]
        await pilot.press("escape")
        await _settle(pilot)
        assert quits == []
        assert app.is_running
        assert [n for n in app._notifications if "q to quit" in n.message]

        # update_inspector never opens a closed Inspector.
        ms.update_inspector(_content(title="ghost"))
        await _settle(pilot)
        assert not ms.inspector_is_open


async def test_inspector_tabs() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        content = InspectorContent(
            title="t",
            tabs=[("Summary", [("", "one")]), ("Raw", [("", "two")])],
        )
        ms.open_inspector(content)
        await _settle(pilot)
        inspector = ms.query_one("#inspector")
        assert inspector.has_class("-tabbed")
        assert inspector.tab_index == 0
        inspector.action_tab(1)
        assert inspector.tab_index == 1
        # Same tab names: the active tab survives a live update.
        ms.update_inspector(
            InspectorContent(
                title="t", tabs=[("Summary", [("", "1")]), ("Raw", [("", "2")])]
            )
        )
        assert inspector.tab_index == 1


async def test_enter_opens_inspector_via_lens_hook(monkeypatch) -> None:
    from sandroid.tui.widgets.files_panel import FilesPanel

    monkeypatch.setattr(
        FilesPanel,
        "inspect_selected",
        lambda self: _content(title="from files"),
        raising=False,
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        # App lens has no hook: Enter stays Start/Resume, no Inspector.
        assert ms.check_action("inspect", ()) is False
        await pilot.press("3")
        await _settle(pilot)
        assert ms.check_action("inspect", ()) is True
        ms.action_inspect()
        await _settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.title == "from files"
        assert ms.inspector_content.lens == "files"


async def test_option_selected_in_active_lens_opens_inspector(monkeypatch) -> None:
    from textual.widgets import OptionList

    from sandroid.tui.widgets.diffs_view import DiffsView

    monkeypatch.setattr(
        DiffsView,
        "inspect_selected",
        lambda self: _content(title="a run"),
        raising=False,
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("4")
        await _settle(pilot)
        runs = ms.query_one("#runs-panel").query(OptionList).first()
        runs.add_option("a row")
        index = runs.option_count - 1
        runs.post_message(
            OptionList.OptionSelected(runs, runs.get_option_at_index(index), index)
        )
        await _settle(pilot)
        assert ms.inspector_is_open
        assert ms.inspector_content.title == "a run"


async def test_chat_and_inspector_share_the_side_slot() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        ms.open_inspector(_content())
        await _settle(pilot)
        await pilot.press("ctrl+y")
        await _settle(pilot)
        assert ms.chat_is_open
        assert not ms.inspector_is_open
        assert is_shown(ms.query_one("#chat-dock"))
        assert not is_shown(ms.query_one("#inspector"))
        ms.open_inspector(_content(title="back"))
        await _settle(pilot)
        assert ms.inspector_is_open
        assert not ms.chat_is_open
        await pilot.press("ctrl+y")
        await _settle(pilot)
        # Esc closes the chat even with the chat input focused.
        assert app.focused is not None
        assert app.focused.id == "chat-input"
        await pilot.press("escape")
        await _settle(pilot)
        assert ms.side_slot_mode is None
        assert ms.lens_widget() in app.focused.ancestors_with_self


async def test_esc_in_watchlist_input_still_leaves_the_input() -> None:
    from textual.widgets import Input

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        ms.open_files_tab("files-watchlist")
        await _settle(pilot)
        ms.open_inspector(_content())
        await _settle(pilot)
        ms.lens_widget("files").open_input("add")
        await _settle(pilot)
        await pilot.press("escape")
        await _settle(pilot)
        # The input's own Esc handling ran; the Inspector is still open.
        assert not isinstance(app.focused, Input)
        assert ms.inspector_is_open


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------


async def test_scope_pill_and_scope_changed_message(monkeypatch) -> None:
    from sandroid.tui.widgets.diffs_view import DiffsView

    received = []
    monkeypatch.setattr(
        DiffsView,
        "on_scope_changed",
        lambda self, message: received.append((message.run_id, message.label)),
        raising=False,
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        header = ms.query_one("#shell-header")
        assert ms.scope is None
        assert header.pill_text == "● LIVE"
        ms.set_scope("20261117-1", label="Run #3")
        await _settle(pilot)
        assert ms.scope == "20261117-1"
        assert header.pill_text == "◆ REVIEW Run #3"
        assert ms.query_one("#scope-pill").has_class("-review")
        assert ("20261117-1", "Run #3") in received
        ms.set_scope(None)
        await _settle(pilot)
        assert header.pill_text == "● LIVE"
        assert received[-1] == (None, None)


async def test_recording_shows_in_the_pill() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        app._set_status_bar_mode(recording=True)
        ms.refresh_status()
        await _settle(pilot)
        assert ms.query_one("#shell-header").pill_text == "● REC"
        app._set_status_bar_mode(recording=False)
        ms.refresh_status()
        await _settle(pilot)
        assert ms.query_one("#shell-header").pill_text == "● LIVE"


# --------------------------------------------------------------------------
# b chord, snapshot picker, footer, keymap
# --------------------------------------------------------------------------


async def test_b_then_digit_toggles_bypass(monkeypatch) -> None:
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.spotlight_panel import BypassChordModal, SpotlightPanel

    toggles: list[str] = []
    objection: list[int] = []
    monkeypatch.setattr(
        SpotlightPanel, "action_toggle_bypass", lambda self, c: toggles.append(c)
    )
    monkeypatch.setattr(
        SandroidTUI, "action_objection", lambda self: objection.append(1)
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        assert app.focused.id == "spotlight-panel"
        await pilot.press("b")
        await _settle(pilot)
        assert isinstance(app.screen, BypassChordModal)
        await pilot.press("2")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert toggles == ["root"]
        assert app.screen.active_lens == "app"  # the digit did not switch lens
        await pilot.press("b", "o")
        await _settle(pilot)
        assert objection == [1]
        await pilot.press("b")
        await _settle(pilot)
        await pilot.press("escape")
        await _settle(pilot)
        assert toggles == ["root"]
        assert type(app.screen).__name__ == "MainScreen"


async def test_zero_and_s_open_the_snapshot_picker() -> None:
    from sandroid.tui.modals import SnapshotPickerModal

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        for key in ("S", "0"):
            await pilot.press(key)
            await _settle(pilot)
            assert isinstance(app.screen, SnapshotPickerModal)
            assert app.screen.panel() is not None
            await pilot.press("escape")
            await _settle(pilot)
            assert type(app.screen).__name__ == "MainScreen"
        app.screen.open_snapshots_tab()  # legacy helper -> picker
        await _settle(pilot)
        assert isinstance(app.screen, SnapshotPickerModal)


async def test_footer_shows_at_most_seven_keys() -> None:
    from sandroid.tui.widgets.sandroid_footer import SandroidFooter

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        for key in ("1", "2", "3", "4"):
            await pilot.press(key)
            await _settle(pilot)
            footer = app.screen.query_one(SandroidFooter)
            keys = list(footer.query("FooterKey"))
            assert 0 < len(keys) <= SandroidFooter.MAX_KEYS
            labels = [k.description for k in keys]
            assert labels[:2] == ["Record", "Play/Replay"]
            assert "Help" in labels


def test_effective_keymap_drops_legacy_ids() -> None:
    from sandroid.tui.app import effective_keymap

    assert effective_keymap(
        {"load_slot_1": "1", "pick_save_slot": "S", "proxy": "Y", "bad": None}
    ) == {"proxy": "Y"}
    assert effective_keymap(None) == {}


async def test_legacy_keybinding_ids_in_config_are_tolerated(monkeypatch) -> None:
    app = _app()
    # The config object may be shared between app instances: monkeypatch so
    # the override never leaks into later tests.
    monkeypatch.setattr(
        app.sandroid_config.tui,
        "keybindings",
        {
            "load_slot_1": "1",
            "load_slot_8": "8",
            "pick_save_slot": "S",
            "show_snapshots": "F2",
        },
    )
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("1")  # still the App lens, not a slot load
        await _settle(pilot)
        assert app.screen.active_lens == "app"
        await pilot.press("question_mark")
        await _settle(pilot)
        help_screen = app.screen
        assert type(help_screen).__name__ == "HelpScreen"
        assert "load_slot_1" not in help_screen._pending
        assert "pick_save_slot" not in help_screen._pending
        assert help_screen._pending.get("show_snapshots") == "F2"
        await pilot.press("escape")
        await _settle(pilot)


@pytest.mark.parametrize("width", [100, 160])
async def test_layout_degrades_gracefully(width) -> None:
    app = _app()
    async with app.run_test(size=(width, 30 if width == 100 else 45)) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        assert ms.query_one("#status-bar").size.height <= 2
        assert ms.query_one("#lens-bar").size.height == 1
        assert ms.query_one("#log-ticker").size.height == 1
        ms.open_inspector(_content())
        await _settle(pilot)
        assert ms.query_one("#lens-host").size.width >= 40
        assert ms.query_one("#side-slot").size.width >= 56 or width >= 140
