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
        assert ms.inspector_is_open  # friTap tab of the Capture status page
        assert ms.query_one("#inspector").tab_index == 1
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
        # The Network lens captions itself on activation; set ours again.
        ms.set_lens_caption("network", "flows", "10 of 247")
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
        # The Runs lens is a DataTable now; mount a stand-in OptionList so the
        # OptionList.OptionSelected path stays covered.
        runs = OptionList("a row")
        await ms.query_one("#runs-panel").mount(runs)
        await _settle(pilot)
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


def test_filter_keys_are_consistent_across_lenses() -> None:
    """``N`` = show hidden noise (Network + Files), ``v`` = review (Runs only).

    The Network lens's app-only filter has a key no other lens and no global
    binding uses.
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen
    from sandroid.tui.widgets.diffs_view import DiffsView
    from sandroid.tui.widgets.files_panel import FilesPanel
    from sandroid.tui.widgets.network_panel import NetworkPanel
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    def keys(cls) -> dict[str, str]:
        return {b.key: b.action for b in cls.BINDINGS if hasattr(b, "key")}

    lenses = {
        "app": keys(SpotlightPanel),
        "network": keys(NetworkPanel),
        "files": keys(FilesPanel),
        "runs": keys(DiffsView),
    }
    assert lenses["network"]["N"] == lenses["files"]["N"] == "toggle_noise"
    assert [lens for lens, bound in lenses.items() if "v" in bound] == ["runs"]
    assert lenses["runs"]["v"] == "review_run"
    app_only = [k for k, a in lenses["network"].items() if a == "toggle_app_only"]
    assert app_only == ["T"]
    others = set(keys(SandroidTUI)) | set(keys(MainScreen))
    for lens, bound in lenses.items():
        if lens != "network":
            others |= set(bound)
    assert "T" not in others


# --------------------------------------------------------------------------
# fix round 2 (live tester on a real emulator)
# --------------------------------------------------------------------------

_SNAPS = [
    {"tag": "tmp", "date": "2026-11-17 16:40", "size": "1.1G"},
    {"tag": "clean_64g", "date": "2026-11-16 10:00", "size": "980M"},
    {"tag": "default_boot", "date": "2026-11-15 09:00", "size": "700M"},
]


def _fake_picker_panel(monkeypatch, snaps):
    """Make every SnapshotsPanel see an emulator and ``snaps`` (no adb)."""
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

    fetches: list[int] = []

    def fake_refresh(self):
        fetches.append(1)
        self._snapshots = [dict(s) for s in snaps]
        self._rebuild_list()

    monkeypatch.setattr(SnapshotsPanel, "_emulator_available", lambda self: True)
    monkeypatch.setattr(SnapshotsPanel, "_avd_name", lambda self: "Test_AVD")
    monkeypatch.setattr(SnapshotsPanel, "_slot_map", lambda self: {})
    monkeypatch.setattr(SnapshotsPanel, "refresh_snapshots", fake_refresh)
    return fetches


async def test_picker_keeps_the_highlighted_snapshot_across_poll_rebuilds(
    monkeypatch,
) -> None:
    """H1: the ~9 s poll rebuilt the list and reset the highlight to row 0,
    so Enter / ``d`` acted on the newest snapshot instead of the picked one.
    """
    from textual.widgets import OptionList

    from sandroid.tui.modals import ConfirmModal, SnapshotPickerModal

    snaps = list(_SNAPS)
    _fake_picker_panel(monkeypatch, snaps)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("S")
        await _settle(pilot)
        picker = app.screen
        assert isinstance(picker, SnapshotPickerModal)
        panel = picker.panel()
        options = panel.query_one("#snapshots-list", OptionList)
        assert panel._highlighted_tag() == "tmp"
        await pilot.press("down")
        await _settle(pilot)
        assert panel._highlighted_tag() == "clean_64g"

        # Poll tick with an unchanged list: the options are not rebuilt.
        cleared: list[int] = []
        original_clear = options.clear_options
        monkeypatch.setattr(
            options, "clear_options", lambda: cleared.append(1) or original_clear()
        )
        panel.refresh_snapshots()
        await _settle(pilot)
        assert cleared == []
        assert panel._highlighted_tag() == "clean_64g"

        # A new snapshot on top (rows shift down): the highlight follows its tag.
        snaps.insert(0, {"tag": "slot-5", "date": "2026-11-17 16:50", "size": "1G"})
        panel.refresh_snapshots()
        await _settle(pilot)
        assert cleared == [1]
        assert options.highlighted == 2
        assert panel._highlighted_tag() == "clean_64g"

        # A fetch that has swapped ``_snapshots`` but not rebuilt yet must not
        # change what Enter acts on.
        panel._snapshots = list(reversed(panel._snapshots))
        assert panel._highlighted_tag() == "clean_64g"
        panel._rebuild_list()
        await _settle(pilot)

        # Enter: the confirm names the highlighted snapshot (with its date).
        await pilot.press("enter")
        await _settle(pilot)
        assert isinstance(app.screen, ConfirmModal)
        assert "'clean_64g'" in app.screen.message_text
        assert "2026-11-16 10:00" in app.screen.message_text
        await pilot.press("escape")
        await _settle(pilot)

        # The highlighted snapshot disappears: stay on the same row position.
        idx = options.highlighted
        snaps[:] = [s for s in snaps if s["tag"] != "clean_64g"]
        panel.refresh_snapshots()
        await _settle(pilot)
        assert options.highlighted == min(idx, len(snaps) - 1)
        assert panel._highlighted_tag() != "clean_64g"


async def test_picker_poll_pauses_while_a_confirm_is_open(monkeypatch) -> None:
    from sandroid.tui.modals import ConfirmModal

    fetches = _fake_picker_panel(monkeypatch, list(_SNAPS))
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("S")
        await _settle(pilot)
        panel = app.screen.panel()
        before = len(fetches)
        panel._poll()
        assert len(fetches) == before + 1
        await pilot.press("d")
        await _settle(pilot)
        assert isinstance(app.screen, ConfirmModal)
        assert "Delete snapshot 'tmp'" in app.screen.message_text
        panel._poll()
        assert len(fetches) == before + 1  # no rebuild under the dialog
        await pilot.press("escape")
        await _settle(pilot)


def test_slot_pointing_at_a_deleted_snapshot(monkeypatch) -> None:
    """L1: a stale slot is reported before the confirm, and deleting a
    snapshot clears the slots that pointed at it.
    """
    from types import SimpleNamespace

    from sandroid.tui.widgets import snapshots_panel as sp

    panel = sp.SnapshotsPanel()
    panel._snapshots = [dict(s) for s in _SNAPS]
    writes: list[tuple[str, str | None]] = []
    monkeypatch.setattr(panel, "_emulator_available", lambda: True)
    monkeypatch.setattr(panel, "_slot_map", lambda: {"3": "slot-3", "1": "tmp"})
    monkeypatch.setattr(panel, "_write_slot", lambda s, t: writes.append((s, t)))
    assert panel.slot_tag("1") == "tmp"
    assert panel.slot_tag("3") is None  # gone: load_slot explains, no confirm
    assert "(gone)" in panel._render_slots()

    toolbox = SimpleNamespace(delete_snapshot=lambda tag: True)
    fake_app = SimpleNamespace(push_screen=lambda screen, cb: cb(True))
    monkeypatch.setattr(sp.SnapshotsPanel, "app", property(lambda self: fake_app))
    monkeypatch.setattr(panel, "_toolbox", lambda: toolbox)
    monkeypatch.setattr(panel, "_highlighted_tag", lambda: "tmp")
    results: list = []
    monkeypatch.setattr(
        panel,
        "_run_action_bg",
        lambda work, label, refresh_after=False: results.append(work()),
    )
    panel.action_delete()
    assert results == [(True, "Deleted 'tmp'")]
    assert writes == [("1", None)]


def test_snapshot_load_restores_selinux_permissive() -> None:
    """M1: a snapshot saved while Enforcing came back Enforcing, and root
    binder calls failed until a restart. The load re-applies setenforce 0.
    """
    import time

    from sandroid.services.emulator_service import EmulatorService

    class FakeAdb:
        def __init__(self, mode: str) -> None:
            self.mode = mode
            self.calls: list[str] = []

        def send_telnet_command(self, command, serial=None):
            return "OK", ""

        def send_adb_command(self, command, serial=None):
            self.calls.append(command)
            if command == "get-state":
                return "device", ""
            if command == "shell getenforce":
                return self.mode + "\n", ""
            if command == "shell setenforce 0":
                self.mode = "Permissive"
            if command == "shell date +%s":
                return str(int(time.time())), ""
            return "", ""

    svc = EmulatorService()
    adb = FakeAdb("Enforcing")
    svc._get_adb = lambda: adb
    assert svc.load_snapshot("clean_64g") is True
    assert "shell setenforce 0" in adb.calls
    assert adb.mode == "Permissive"

    adb = FakeAdb("Permissive")
    svc._get_adb = lambda: adb
    assert svc.load_snapshot("clean_64g") is True
    assert "shell setenforce 0" not in adb.calls

    # setenforce refused (no root): falls back to su, then adb root; never raises.
    class NoRoot(FakeAdb):
        def send_adb_command(self, command, serial=None):
            if command == "shell setenforce 0":
                self.calls.append(command)
                return "", "setenforce: Permission denied"
            return super().send_adb_command(command, serial)

    adb = NoRoot("Enforcing")
    assert svc._restore_selinux_permissive(adb, None) is False
    assert "shell su 0 setenforce 0" in adb.calls
    assert "root" in adb.calls


def test_picker_load_restarts_frida_server(monkeypatch) -> None:
    """M1: after a picker load frida-server is re-started (auto-start)."""
    import threading
    from types import SimpleNamespace

    from sandroid.tui.widgets import snapshots_panel as sp

    started = threading.Event()
    panel = sp.SnapshotsPanel()
    panel._app_ref = SimpleNamespace(_auto_start_frida_server=started.set)
    toolbox = SimpleNamespace(load_snapshot=lambda tag: True)
    fake_app = SimpleNamespace(push_screen=lambda screen, cb: cb(True))
    monkeypatch.setattr(sp.SnapshotsPanel, "app", property(lambda self: fake_app))
    monkeypatch.setattr(panel, "_require_emulator", lambda: True)
    monkeypatch.setattr(panel, "_toolbox", lambda: toolbox)
    monkeypatch.setattr(panel, "_highlighted_tag", lambda: "clean_64g")
    monkeypatch.setattr(panel, "_post", lambda fn, *a: None)
    monkeypatch.setattr(sp, "_forget_device_handles", lambda: None)
    results: list = []
    monkeypatch.setattr(
        panel,
        "_run_action_bg",
        lambda work, label, refresh_after=False: results.append(work()),
    )
    panel.action_load()
    assert results == [(True, "Loaded 'clean_64g'")]
    assert started.wait(2)


async def test_inspector_tabs_switch_while_focus_stays_in_the_lens() -> None:
    """M2: ←/→ only worked after Tab. ``[``/``]`` switch tabs wherever focus
    is; ←/→ too, unless the focused widget uses them (a DataTable).
    """
    from textual.widgets import DataTable

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        tabs = [("Summary", [("", "1")]), ("Diff", [("", "2")]), ("Events", [])]
        ms.open_inspector(InspectorContent(title="t", tabs=tabs))
        await _settle(pilot)
        inspector = ms.query_one("#inspector")
        assert ms.lens_widget() in app.focused.ancestors_with_self
        assert "[ ] tabs" in str(inspector.border_subtitle)
        await pilot.press("right_square_bracket")
        assert inspector.tab_index == 1
        await pilot.press("right")
        assert inspector.tab_index == 2
        await pilot.press("left_square_bracket", "left_square_bracket")
        assert inspector.tab_index == 0
        await pilot.press("left")
        assert inspector.tab_index == 2  # wraps

        # Runs lens with its DataTable focused: [ ] still work (←/→ stay the
        # table's while it can scroll sideways; Textual skips them otherwise).
        await pilot.press("4")
        await _settle(pilot)
        ms.open_inspector(InspectorContent(title="run", tabs=tabs))
        await _settle(pilot)
        # (No runs here: show the table -- a hidden widget never keeps focus.)
        ms.query_one("#runs-panel").set_class(True, "-has-runs")
        table = ms.query_one("#runs-panel").query_one(DataTable)
        table.focus()
        await _settle(pilot)
        assert app.focused is table
        start = inspector.tab_index
        await pilot.press("right_square_bracket")
        assert inspector.tab_index == (start + 1) % 3

        # Inspector closed: the keys are inert.
        ms.close_inspector()
        await _settle(pilot)
        assert ms.check_action("inspector_tab", (1,)) is False


async def test_lens_switch_closes_the_inspector_of_another_lens() -> None:
    """M7: a Files Inspector ("w watch") stayed open over the App lens, where
    ``w`` is the global PCAP key.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("3")
        await _settle(pilot)
        ms.open_inspector(_content(title="a file"))
        await _settle(pilot)
        assert ms.inspector_content.lens == "files"
        await pilot.press("1")
        await _settle(pilot)
        assert not ms.inspector_is_open
        assert ms.lens_widget() in app.focused.ancestors_with_self
        # Re-selecting the lens that owns the Inspector keeps it open.
        await pilot.press("3")
        await _settle(pilot)
        ms.open_inspector(_content(title="a file"))
        await _settle(pilot)
        ms.switch_lens("files")
        await _settle(pilot)
        assert ms.inspector_is_open


def test_bypass_digits_mean_the_same_in_chord_and_objection() -> None:
    """M3: ``b`` 3 was Frida but Objection's [3] was Emulator."""
    from sandroid.tui.modals.objection_modal import (
        _OBJECTION_OPTIONS,
        BYPASS_KEYS,
        ObjectionModal,
    )
    from sandroid.tui.widgets.spotlight_panel import _BYPASS_TOGGLES

    chord = {key: cat for key, cat, _label in _BYPASS_TOGGLES}
    assert chord == {key: cat for key, cat, _label in BYPASS_KEYS}
    objection = {
        b.key: b.action.removeprefix("toggle_")
        for b in ObjectionModal.BINDINGS
        if b.action.startswith("toggle_") and b.action != "toggle_spawn"
    }
    for key, category in objection.items():
        if key.isdigit():
            assert chord[key] == category, key
        assert category in _OBJECTION_OPTIONS
    assert objection["e"] == "emulator"


async def test_objection_modal_digits_toggle_the_chord_categories() -> None:
    from textual.app import App

    from sandroid.tui.modals.objection_modal import ObjectionModal

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(ObjectionModal(package_name="org.example"))

    app = Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await _settle(pilot)
        modal = app.screen
        assert isinstance(modal, ObjectionModal)
        await pilot.press("3")  # Frida, as in the b chord
        assert modal.config.frida_detection is True
        assert modal.config.emulator_detection is False
        await pilot.press("e")
        assert modal.config.emulator_detection is True
        text = str(modal.query_one("#option-frida").render())
        assert "●" in text
        assert "3" in text


@pytest.mark.parametrize("size", [(80, 24), (160, 45)])
async def test_help_fits_small_terminals_and_lists_every_global_key(size) -> None:
    """M4: at 80x24 the help was wider than the screen with one visible row,
    and Ctrl+Y / Ctrl+B / , / Ctrl+C were missing.
    """
    import re

    from rich.text import Text
    from textual.widgets import OptionList

    app = _app()
    async with app.run_test(size=size) as pilot:
        await _boot(app, pilot)
        await pilot.press("question_mark")
        await _settle(pilot)
        help_screen = app.screen
        assert type(help_screen).__name__ == "HelpScreen"
        container = help_screen.query_one("#kb-container")
        assert container.region.right <= size[0]
        options = help_screen.query_one("#kb-list", OptionList)
        assert options.size.height >= (12 if size[1] == 24 else 20)
        rows = [
            Text.from_markup(str(options.get_option_at_index(i).prompt)).plain
            for i in range(options.option_count)
        ]
        text = "\n".join(rows)
        for key in ("[Ctrl+Y]", "[Ctrl+B]", "[,]", "[Ctrl+C]", "[`]", "[=]"):
            assert key in text, key
        assert "Level up" not in text
        assert "Grave_Accent" not in text
        assert "Equals_Sign" not in text
        assert "any panel" not in text
        # Each row fits on one line of the list.
        width = options.scrollable_content_region.width
        assert max(len(r) for r in rows) <= width
        # Lenses in key order; one row per action within a section.
        nav = [r for r in rows if re.match(r"(App|Network|Files|Runs) lens ", r)]
        assert [n.split()[0] for n in nav[:4]] == ["App", "Network", "Files", "Runs"]
        bypass = rows.index(next(r for r in rows if "b bypass" in r))
        section = rows[bypass + 1 : bypass + 7]
        assert sum("Objection" in r for r in section) == 1
        await pilot.press("escape")


async def test_chat_banner_wraps_to_the_panel_width() -> None:
    """M5: the privacy warning was wrapped at the hidden panel's width and
    clipped at the visible panel's edge.
    """
    from textual.widgets import RichLog

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("ctrl+y")
        await _settle(pilot, 8)
        log = app.screen.query_one("#chat-log", RichLog)
        width = log.scrollable_content_region.width
        assert log.lines
        assert max(line.cell_length for line in log.lines) <= width


async def test_ui_callbacks_from_threads_can_start_timers() -> None:
    """M6: the first ``b 1`` logged ``LookupError: active_app`` -- a worker
    marshalled a refresh with a bare ``call_soon_threadsafe`` (no app
    context) and that refresh started a timer.
    """
    import threading

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        panel = app.screen.query_one("#spotlight-panel")
        fired: list[int] = []
        errors: list = []
        loop = panel._main_loop
        loop.set_exception_handler(lambda _loop, ctx: errors.append(ctx))

        def start_timer() -> None:
            panel.set_timer(0.01, lambda: fired.append(1))

        worker = threading.Thread(target=panel._post, args=(start_timer,))
        worker.start()
        worker.join()
        for _ in range(10):
            await pilot.pause(0.05)
            if fired:
                break
        loop.set_exception_handler(None)
        assert fired == [1]
        assert errors == []


async def test_settings_have_no_default_view_row() -> None:
    """L3: views were removed in 2.1; Settings still offered "Default View"."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("comma")
        await _settle(pilot, 8)
        assert type(app.screen).__name__ == "SettingsScreen"
        assert not app.screen.query("#setting-analysis--default_view")
        await pilot.press("escape")


# --------------------------------------------------------------------------
# fix round 3: quit paths, thread hand-off, log ticker
# --------------------------------------------------------------------------


async def test_ctrl_q_asks_before_quitting(monkeypatch) -> None:
    """Textual's own Ctrl+Q quit at once, without the dialog and cleanup."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        calls: list[str] = []
        monkeypatch.setattr(
            app._quit_controller, "request_quit", lambda: calls.append("ctrl+q")
        )
        await pilot.press("ctrl+q")
        await _settle(pilot)
        assert calls == ["ctrl+q"]
        assert app.is_running
        assert app.return_code is None


async def test_quit_dialog_exit_runs_the_cleanup(monkeypatch) -> None:
    """H1: q -> y called the base exit and skipped force_exit.

    mitmweb and the device proxy stayed behind.
    """
    from sandroid.tui.controllers import quit_controller as qc

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        cleaned: list[int] = []
        monkeypatch.setattr(
            app._quit_controller, "force_exit", lambda: cleaned.append(1)
        )
        monkeypatch.setattr(qc.QuitController, "_quit_notes", staticmethod(list))
        await pilot.press("q")
        await _settle(pilot)
        assert type(app.screen).__name__ == "QuitConfirmModal"
        await pilot.press("y")
        for _ in range(40):
            await pilot.pause(0.05)
            if app._exit:
                break
        assert cleaned == [1]
        assert app._exit
        assert app.return_code == 0


async def test_exit_does_not_wait_for_a_hung_cleanup(monkeypatch) -> None:
    """H1: a friTap agent that cannot unload must not hold the quit up."""
    import threading

    app = _app()
    release = threading.Event()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        monkeypatch.setattr(type(app), "QUIT_CLEANUP_BUDGET", 0.3)
        monkeypatch.setattr(
            app._quit_controller, "force_exit", lambda: release.wait(10)
        )
        app.exit()
        for _ in range(40):
            await pilot.pause(0.05)
            if app._exit:
                break
        assert app._exit  # posted although the cleanup still "runs"
        app.exit()  # a second request while cleaning up: harmless
    release.set()


def test_exit_watchdog_tears_down_and_exits_when_the_quit_hangs(monkeypatch):
    """H1: with the UI loop stuck, the watchdog still stops mitmweb, clears
    the device proxy and ends the process -- only when the launcher enabled it.
    """
    import threading

    from sandroid.tui.controllers import quit_controller as qc

    exits: list[tuple[int, str]] = []
    fired = threading.Event()

    def _fake_exit(code: int, why: str) -> None:
        exits.append((code, why))
        fired.set()

    monkeypatch.setattr(qc, "_force_process_exit", _fake_exit)
    monkeypatch.setattr(qc, "EXIT_DEADLINE", 0.1)
    try:
        qc.enable_hard_exit(False)
        assert not qc.arm_exit_watchdog()  # tests / embedders: never armed
        qc.enable_hard_exit(True)
        assert qc.arm_exit_watchdog(exit_code=3)
        assert qc.arm_exit_watchdog()  # idempotent
        assert fired.wait(5)
        assert exits[0][0] == 0  # the second arm kept the code (default 0)
        assert "did not finish" in exits[0][1]
    finally:
        qc.enable_hard_exit(False)


def test_force_exit_stops_mitmweb_first_and_bounds_hung_steps(monkeypatch):
    """Every quit path tears down mitmweb + the device proxy first.

    A stuck task stop (friTap agent that cannot unload) is left behind after
    a timeout.
    """
    import threading
    import time as _time

    from sandroid.services import mitmproxy_service as ms
    from sandroid.tui.controllers import quit_controller as qc

    order: list[str] = []

    class _Svc:
        def shutdown(self, timeout=2.0):
            order.append("mitm")

    monkeypatch.setattr(ms, "_INSTANCE", _Svc())
    blocker = threading.Event()

    class _Tasks:
        def stop_all(self):
            order.append("tasks")
            blocker.wait(10)

    from sandroid import services

    monkeypatch.setattr(services, "get_task_service", lambda: _Tasks())
    real_bounded = qc.run_bounded
    monkeypatch.setattr(
        qc, "run_bounded", lambda name, fn, timeout: real_bounded(name, fn, 0.2)
    )
    started = _time.monotonic()
    qc.QuitController().force_exit()
    blocker.set()
    assert order[:2] == ["mitm", "tasks"]
    assert _time.monotonic() - started < 5


def test_quit_dialog_says_what_quitting_tears_down(monkeypatch):
    """L15: the dialog did not mention mitmweb or the device proxy."""
    from types import SimpleNamespace

    from sandroid.services import mitmproxy_service as ms
    from sandroid.tui.controllers.quit_controller import QuitController

    monkeypatch.setattr(
        ms,
        "_INSTANCE",
        SimpleNamespace(is_running=lambda: True, owned_device_proxy="10.0.2.2:8090"),
    )
    notes = QuitController._quit_notes()
    assert notes[:2] == ["stops mitmweb", "clears the device proxy"]


def test_ui_dispatcher_runs_in_the_ui_context_and_reports_once(caplog):
    import asyncio
    import contextvars
    import logging
    import threading

    from sandroid.tui.utils.ui_thread import UiDispatcher

    marker: contextvars.ContextVar[str] = contextvars.ContextVar("marker")
    seen: list[str] = []

    def boom() -> None:
        raise ValueError("x")

    async def main() -> None:
        marker.set("ui")
        ui = UiDispatcher.capture()
        assert ui.bound

        def worker() -> None:
            ui.post(lambda: seen.append(marker.get("none")))
            for _ in range(3):
                ui.post(boom)

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        for _ in range(5):
            await asyncio.sleep(0)

    with caplog.at_level(logging.DEBUG, logger="sandroid.tui.utils.ui_thread"):
        asyncio.run(main())
    assert seen == ["ui"]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert not UiDispatcher().post(lambda: None)  # unbound: nothing scheduled


async def test_ticker_shows_human_lines_not_adb_commands() -> None:
    """M7/M2: the ticker showed raw adb command lines and traceback tails."""
    from sandroid.tui.widgets import ActivityLog

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        log = ms.query_one("#activity-log", ActivityLog)
        ticker = ms.query_one("#log-ticker")
        raw = (
            "ADB command warning (-s emulator-5554 shell '{ printf "
            "'\"'\"'GET http://mitm.it/ HTTP/1.1'\"'\"'; sleep 2; }' | toybox nc "
            "-w 4 10.0.2.2 8090'): nc: connect: Network is unreachable"
        )
        log.log_warning(raw)
        await _settle(pilot)
        assert "adb: nc: connect: Network is unreachable" in ticker.last_line
        assert "printf" not in ticker.last_line
        assert "printf" in "\n".join(log._plain_lines)  # full line in the drawer
        log.log_error(
            "Task exception was never retrieved\nTraceback (most recent call "
            "last):\n  File x\nLookupError: <ContextVar name='active_app'>"
        )
        await _settle(pilot)
        assert "Task exception was never retrieved" in ticker.last_line


async def test_recurring_errors_are_folded(monkeypatch) -> None:
    """M2: one error per network flow drowned the drawer and the ticker."""
    from sandroid.tui.widgets import ActivityLog

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        log = app.screen.query_one("#activity-log", ActivityLog)
        before = len(log._plain_lines)
        for i in range(6):
            log.log_error(
                f"Task exception was never retrieved\nfuture: <Task "
                f"name='set_timer#{i}' at 0x{i:x}ff>\nLookupError: active_app"
            )
        assert len(log._plain_lines) == before + 1
        log.log_error("a different problem")
        assert len(log._plain_lines) == before + 2
        monkeypatch.setattr(ActivityLog, "REPEAT_WINDOW", 0.0)
        log.log_error("Task exception was never retrieved\nLookupError: active_app")
        assert "+5 more like this" in log._plain_lines[-1]


async def test_drawer_focus_offers_no_inspect_and_has_no_hscroll() -> None:
    """L: a focused log drawer showed "⏎ Inspect"; a stray scrollbar thumb."""
    from sandroid.tui.widgets import ActivityLog

    app = _app()
    async with app.run_test(size=(100, 30)) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        await pilot.press("2")  # a lens with an Inspector
        await _settle(pilot)
        assert ms.check_action("inspect", ()) is True
        ms.toggle_log_drawer()
        await _settle(pilot)
        log = ms.query_one("#activity-log", ActivityLog)
        log.focus()
        await _settle(pilot)
        assert ms.check_action("inspect", ()) is False
        assert log.styles.overflow_x == "hidden"
        log.log_info("x" * 300)
        await _settle(pilot)
        assert log.max_scroll_x == 0


# --------------------------------------------------------------------------
# fix round 4: quit always asks; keys after confirm; status under modals
# --------------------------------------------------------------------------


async def test_q_asks_first_and_stops_running_tools_off_the_ui_thread() -> None:
    """NEW-1 / Files M7: with friTap or the file monitor running, ``q``
    stopped them on the UI thread instead of asking (~6 s freeze); the ``y``
    meant for the dialog then opened Proxy Settings and Sandroid stayed up.
    """
    import threading
    import time

    from sandroid.services import get_task_service

    stops: list[tuple[str, bool]] = []

    def _slow_stop(name: str):
        def _stop() -> None:
            time.sleep(0.6)
            stops.append((name, threading.current_thread() is threading.main_thread()))

        return _stop

    tasks = get_task_service()
    app = _app()
    try:
        async with app.run_test(size=SIZE) as pilot:
            await _boot(app, pilot)
            for name, display in (("fritap", "FriTap"), ("monitor", "Monitor")):
                tasks.register(
                    name=name,
                    display_name=display,
                    instance=None,
                    stop_callback=_slow_stop(name),
                )
            await _settle(pilot)
            await pilot.press("q")
            await _settle(pilot)
            modal = app.screen
            assert type(modal).__name__ == "QuitConfirmModal"
            assert stops == []  # nothing stopped before the confirm
            notes = str(modal.query_one("#quit-notes").render())
            assert "stops friTap" in notes
            assert "stops the file monitor" in notes
            await pilot.press("y")
            await _settle(pilot, 2)
            # Still up, as a progress note that swallows keys.
            assert app.screen is modal
            assert modal.quitting
            assert "Quitting" in str(modal.query_one("#quit-title").render())
            for key in ("y", "escape", "M", "q", "n"):
                await pilot.press(key)
            await _settle(pilot, 2)
            assert app.screen is modal
            assert app.check_action("toggle_proxy", ()) is False
            for _ in range(80):
                await pilot.pause(0.05)
                if app._exit:
                    break
            assert app._exit
            assert sorted(stops) == [("fritap", False), ("monitor", False)]
    finally:
        for name in ("fritap", "monitor"):
            tasks.unregister(name)


async def test_q_asks_even_with_a_resident_frida_script(monkeypatch) -> None:
    """R2-N2: the bypass script stays loaded after ``b`` turns every
    category off, unregistered from the TaskService. ``q`` then silently
    stopped this "untracked Frida job" (on the UI thread) instead of asking,
    so the following ``y`` landed on Proxy Settings.
    """
    from sandroid.core import background_tracker as bt

    cleaned: list[int] = []
    report = bt.BackgroundWorkReport(
        untracked_frida_jobs=[
            bt.UntrackedWork(
                work_type="frida_job",
                name="Detection Bypass",
                details="job_id=1",
                identifier="1",
            )
        ]
    )
    monkeypatch.setattr(
        bt.BackgroundWorkTracker, "detect_untracked_work", lambda self: report
    )
    monkeypatch.setattr(
        bt.BackgroundWorkTracker,
        "force_cleanup",
        lambda self, rep: cleaned.append(1) or [],
    )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        await pilot.press("q")
        await _settle(pilot)
        assert type(app.screen).__name__ == "QuitConfirmModal"
        assert cleaned == []
        await pilot.press("ctrl+c")  # a second quit key does not stack dialogs
        await _settle(pilot)
        assert (
            sum(type(s).__name__ == "QuitConfirmModal" for s in app.screen_stack) == 1
        )
        await pilot.press("n")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"


async def test_q_after_closing_the_objection_dialog_asks(monkeypatch) -> None:
    """R2-N2 (b): ``b`` ``o`` Esc, then ``q`` must reach the quit dialog."""
    from types import SimpleNamespace

    from sandroid.tui import app as app_mod

    monkeypatch.setattr(
        app_mod,
        "get_spotlight_service",
        lambda: SimpleNamespace(
            has_app=lambda: True, get_app_tuple=lambda: ("org.example", 0)
        ),
    )
    app = _app()
    async with app.run_test(size=(80, 24)) as pilot:
        await _boot(app, pilot)
        await pilot.press("1")
        await _settle(pilot)
        await pilot.press("b")
        await _settle(pilot)
        await pilot.press("o")
        await _settle(pilot)
        assert type(app.screen).__name__ == "ObjectionModal"
        await pilot.press("escape")
        await _settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        await pilot.press("q")
        await _settle(pilot)
        assert type(app.screen).__name__ == "QuitConfirmModal"
        await pilot.press("n")
        await _settle(pilot)


async def test_status_bar_refreshes_while_a_modal_is_open(monkeypatch) -> None:
    """R2-N1: the snapshot picker stays open after a load; the post-load
    frida-server restart's status refresh found no status bar there, so the
    strip said "Frida ○ off" for minutes.
    """
    from sandroid.tui.widgets.status_bar import StatusBar

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await _boot(app, pilot)
        bar = app.screen.query_one("#status-bar", StatusBar)
        calls: list[int] = []
        monkeypatch.setattr(bar, "update_from_toolbox", lambda: calls.append(1))
        await pilot.press("question_mark")
        await _settle(pilot)
        assert type(app.screen).__name__ != "MainScreen"
        app._update_status_bar()  # what _auto_start_frida_server calls
        assert calls == [1]
        app._refresh_status_bar()  # the proxy controller's refresh
        assert calls == [1, 1]
        await pilot.press("escape")


def test_strip_keeps_the_device_proxy_while_it_cannot_be_read(monkeypatch):
    """NEW-5: during the ^N settle the settings service is down ("Broken
    pipe"); the strip said "device ○" while the caption said "device ✓",
    and each read logged "Invalid proxy format".
    """
    from sandroid.core.proxy_manager import ProxyManager, ProxyStatus
    from sandroid.tui.widgets.status_bar import StatusBar

    bar = StatusBar()
    bar.active_device = "emulator-5554"
    bar.proxy_address = "10.0.2.2:8090"
    answer = {"v": (ProxyStatus.ERROR, None)}
    monkeypatch.setattr(ProxyManager, "get_proxy_settings", lambda self: answer["v"])
    monkeypatch.setattr(StatusBar, "_schedule_frida_check", lambda self: None)
    from sandroid.core.toolbox import Toolbox

    def _no_device_manager(*_args):
        raise RuntimeError("keeps the active device set above")

    monkeypatch.setattr(Toolbox, "get_device_manager", _no_device_manager)
    bar.update_from_toolbox()
    assert bar.proxy_address == "10.0.2.2:8090"
    answer["v"] = (ProxyStatus.NOT_SET, None)
    bar.update_from_toolbox()
    assert bar.proxy_address == ""


# --------------------------------------------------------------------------
# E2E Files/Firefox: the log drawer wrapped at 20 columns, paths in red
# --------------------------------------------------------------------------


@pytest.mark.parametrize("size", [(200, 50), (100, 30)])
async def test_drawer_lines_use_the_drawer_width_and_only_errors_are_red(
    size,
) -> None:
    """Lines written while the drawer was closed (width 0) wrapped at
    ``min_width`` = 20 columns, and the repr highlighter painted paths
    magenta (red on the dark theme); a normal stop was red too, twice.
    """
    from sandroid.tui.widgets import ActivityLog

    app = _app()
    async with app.run_test(size=size) as pilot:
        await _boot(app, pilot)
        ms = app.screen
        log = ms.query_one("#activity-log", ActivityLog)
        ms.toggle_log_drawer()  # open once (size known), then close
        await _settle(pilot)
        ms.toggle_log_drawer()
        await _settle(pilot)
        path = (
            "/data/data/org.mozilla.firefox/cache/k3m7yjvw.default/cache2/"
            "entries/98651ACF954B76241C3F4101CF4BC5B2C0B66362"
        )
        log.log_info(f"Pulled {path} to /private/tmp/results/files/{path[11:]}")
        log.log_task_stopped("Monitor")
        log.log_task_stopped("Monitor")  # the same stop from a second channel
        await _settle(pilot)
        ms.toggle_log_drawer()
        await _settle(pilot)
        width = log.scrollable_content_region.width
        assert width > size[0] - 10
        texts = ["".join(seg.text for seg in strip).rstrip() for strip in log.lines]
        pulled = [i for i, t in enumerate(texts) if "INFO:" in t and "Pulled" in t]
        assert pulled, texts
        # The long line uses the drawer width (it wrapped at 20 columns).
        stop = next(i for i, t in enumerate(texts) if "<<< Stopped" in t)
        assert stop - pulled[0] <= (3 if size[0] >= 200 else 6)  # 20 cols: 13
        assert max(len(t) for t in texts[pulled[0] : stop]) > 60
        assert sum("<<< Stopped: Monitor" in t for t in texts) == 1
        # No red / magenta on the INFO line (paths) or the normal stop.
        red = {"#fb7185", "#ff5555", "magenta", "bright_magenta"}
        for strip in log.lines[pulled[0] :]:
            for seg in strip:
                color = seg.style.color if seg.style else None
                name = color.name if color is not None else ""
                assert name not in red, (seg.text, name)
        # A resize re-wraps what is already there.
        lines_before = len(log.lines)
        await pilot.resize_terminal(size[0] // 2, size[1])
        await _settle(pilot, 8)
        assert len(log.lines) > lines_before
        # An ERROR line is still coloured.
        log.log_error("pull failed")
        await _settle(pilot)
        assert any(
            seg.style and seg.style.color and "ERROR" in seg.text
            for seg in log.lines[-1]
        )


# --------------------------------------------------------------------------
# E2E Files/Firefox: ? opens on the current lens; shadowed keys explained
# --------------------------------------------------------------------------


@pytest.mark.parametrize("size", [(200, 50), (100, 30)])
async def test_help_opens_on_the_current_lens_and_explains_shadowed_keys(
    size,
) -> None:
    from rich.text import Text
    from textual.widgets import OptionList

    app = _app()
    async with app.run_test(size=size) as pilot:
        await _boot(app, pilot)
        await pilot.press("3")
        await _settle(pilot)
        await pilot.press("question_mark")
        await _settle(pilot)
        help_screen = app.screen
        assert type(help_screen).__name__ == "HelpScreen"
        options = help_screen.query_one("#kb-list", OptionList)
        rows = [
            Text.from_markup(str(options.get_option_at_index(i).prompt)).plain
            for i in range(options.option_count)
        ]
        heads = [r.strip("─ ") for r in rows if r.startswith("──")]
        # Current lens first, then the Inspector, then the global keys, then
        # the other lenses.
        assert heads[0] == "Files lens"
        assert heads[1] == "Inspector (while open)"
        assert heads[2] == "General"
        assert heads.index("Recording") < heads.index("App lens")
        assert heads.index("App lens") < heads.index("Network lens")
        assert heads.index("Network lens") < heads.index("Runs lens")
        # The list opens on the Files lens's first key, scrolled to the top.
        assert options.highlighted == 1
        assert options.scroll_offset.y == 0
        # Files w / n / O: the lens meaning, marked as overriding the global.
        files = rows[1 : rows.index(next(r for r in rows[1:] if r.startswith("──")))]
        watch = next(r for r in files if r.rstrip().endswith("[w]"))
        assert watch.startswith("Watch · overrides global w = ")
        assert "network capture" in watch.lower()
        assert sum("overrides global" in r for r in files) == 3  # w, n, O
        # The global rows say where the key means something else.
        rest = rows[len(files) + 1 :]
        capture = next(r for r in rest if r.rstrip().endswith("[w]"))
        assert "not in Files" in capture
        install = next(r for r in rest if r.rstrip().endswith("[n]"))
        assert "not in Files, Runs" in install
        # The App lens's b (bypass) is marked in its own section too.
        app_start = rows.index(next(r for r in rows if r.startswith("── App lens ──")))
        bypass = next(r for r in rows[app_start:] if r.rstrip().endswith("[b]"))
        assert "overrides global" in bypass
        # Every row fits the list.
        width = options.scrollable_content_region.width
        assert max(len(r) for r in rows) <= width
        # The detail pane (wide terminals) spells the override out.
        if size[0] >= 200:
            options.highlighted = rows.index(watch)
            await _settle(pilot)
            detail = str(help_screen.query_one("#kb-detail").render())
            assert "Overrides the global key w = " in detail
        await pilot.press("escape")
