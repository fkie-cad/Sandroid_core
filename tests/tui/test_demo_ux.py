"""Usability / keybinding regressions found in the 2.1 live demo rehearsal.

Covers the global Record/Play keys, Shift-aware key labels, the confirm
guard on snapshot-slot loading (picker), Shift+Arrow focus handling, the Record
settings modal and smaller fixes (recording duration, ...). The full
``SandroidTUI`` is driven through Textual's pilot; the suite-wide conftest
blocks every device access, so "no device connected" is the natural state.
"""

from __future__ import annotations

import time

import pytest
from pilot_helpers import boot, settle

from sandroid.tui.key_display import format_key
from sandroid.tui.utils.recording_wrapper import RecordingWrapper

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

SIZE = (200, 50)


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _messages(app) -> list[str]:
    return [n.message for n in app._notifications]


# --------------------------------------------------------------------------
# key labels
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "compact", "long"),
    [
        ("r", "r", "r"),
        ("R", "Shift+R", "Shift+R"),
        ("c", "c", "c"),
        ("C", "Shift+C", "Shift+C"),
        ("ctrl+b", "^b", "Ctrl+B"),
        ("ctrl+shift+p", "^Shift+P", "Ctrl+Shift+P"),
        ("shift+right", "Shift+Right", "Shift+Right"),
        ("question_mark", "?", "?"),
        ("enter", "Enter", "Enter"),
        ("1", "1", "1"),
    ],
)
def test_format_key_keeps_shift_visible(key, compact, long) -> None:
    assert format_key(key, "compact") == compact
    assert format_key(key, "long") == long


def test_lower_and_upper_case_keys_never_render_alike() -> None:
    for letter in "cefgrp":
        assert format_key(letter) != format_key(letter.upper())
        assert format_key(letter, "compact") != format_key(letter.upper(), "compact")


# --------------------------------------------------------------------------
# recording wrapper
# --------------------------------------------------------------------------


def test_recording_wrapper_stop_reports_real_duration(tmp_path) -> None:
    wrapper = RecordingWrapper(output_file=str(tmp_path / "rec.txt"))
    wrapper._start_time = time.time() - 42
    assert wrapper.stop() == 42
    assert wrapper.elapsed_seconds == 42
    # idempotent
    assert wrapper.stop() == 42


# --------------------------------------------------------------------------
# global Record / Play
# --------------------------------------------------------------------------


def test_record_play_are_global_rebindable_app_bindings() -> None:
    from sandroid.tui.app import SandroidTUI

    by_id = {b.id: b for b in SandroidTUI.BINDINGS if b.id}
    assert by_id["record"].key == "r"
    assert by_id["play"].key == "p"
    assert not by_id["record"].priority  # an Input must still receive "r"


async def test_r_on_main_screen_without_device_explains_why() -> None:
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        await pilot.press("r")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"
        assert any("No device connected" in m for m in _messages(app))


async def test_p_without_recording_explains_and_stays_put(monkeypatch) -> None:
    from sandroid.tui.app import SandroidTUI

    monkeypatch.setattr(SandroidTUI, "_active_device", lambda self: object())
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        monkeypatch.setattr(app._recording_controller, "has_recording", lambda: False)
        started = []
        monkeypatch.setattr(
            app._recording_controller, "open_review", lambda: started.append(1)
        )
        await pilot.press("p")
        await settle(pilot)
        assert started == []
        assert any("Nothing recorded yet" in m for m in _messages(app))
        assert app.screen.query_one("#lens-body").current == "spotlight-panel"


# --------------------------------------------------------------------------
# snapshot slots: digits are lenses; slots load from the picker, confirmed
# --------------------------------------------------------------------------


async def test_slot_digit_in_picker_needs_confirm(monkeypatch) -> None:
    from sandroid.tui.modals import ConfirmModal, SnapshotPickerModal
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

    loads: list[str] = []
    monkeypatch.setattr(SnapshotsPanel, "slot_tag", lambda self, s: "clean")
    monkeypatch.setattr(SnapshotsPanel, "load_slot", lambda self, s: loads.append(s))
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        await pilot.press("S")
        await settle(pilot)
        assert isinstance(app.screen, SnapshotPickerModal)
        await pilot.press("7")
        await settle(pilot)
        assert loads == []
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("escape")  # cancel: nothing loaded
        await settle(pilot)
        assert loads == []
        await pilot.press("7")
        await settle(pilot)
        app.screen.dismiss(True)
        await settle(pilot)
        assert loads == ["7"]


async def test_digit_on_main_screen_switches_lens_not_slot(monkeypatch) -> None:
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel
    from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

    toggles: list[str] = []
    loads: list[str] = []
    monkeypatch.setattr(
        SpotlightPanel, "action_toggle_bypass", lambda self, c: toggles.append(c)
    )
    monkeypatch.setattr(SnapshotsPanel, "load_slot", lambda self, s: loads.append(s))
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await boot(app, pilot)
        assert app.focused.id == "spotlight-panel"
        await pilot.press("2")
        await settle(pilot)
        assert app.screen.active_lens == "network"
        assert toggles == []
        assert loads == []


# --------------------------------------------------------------------------
# Shift+Arrow focus
# --------------------------------------------------------------------------


async def test_shift_arrow_moves_focus_into_each_panel() -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        seen = []
        # App -> Network -> Files -> Sessions -> Timeline -> Identity -> App
        for _ in range(6):
            await pilot.press("shift+right")
            await settle(pilot)
            current = app.screen.query_one("#lens-body").current
            panel = app.screen.query_one(f"#{current}")
            assert app.focused is not None
            assert panel in app.focused.ancestors_with_self, current
            seen.append(current)
        assert seen[-1] == "spotlight-panel"


async def test_files_lens_has_no_subtabs_to_get_stuck_in() -> None:
    """The Files lens is one table: Shift+Down is a no-op and Shift+Right
    moves on to the next lens, never into the lens's inline input.
    """
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        app.screen.open_files_tab()
        await settle(pilot)
        await pilot.press("shift+down")
        await pilot.press("shift+right")
        await settle(pilot)
        assert app.screen.active_lens == "runs"
        assert type(app.focused).__name__ != "_LensInput"


# --------------------------------------------------------------------------
# Record settings / recording modal
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# ? catalog
# --------------------------------------------------------------------------


async def test_help_catalog_is_case_aware_and_lists_panel_keys() -> None:
    from textual.widgets import OptionList

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        await pilot.press("question_mark")
        await settle(pilot)
        assert type(app.screen).__name__ == "HelpScreen"
        options = app.screen.query_one("#kb-list", OptionList)
        rows = [
            str(options.get_option_at_index(i).prompt)
            for i in range(options.option_count)
        ]
        text = "\n".join(rows)
        assert "[Shift+C]" in text  # spotlight spawn
        assert "\\[c]" in text or "[c]" in text  # spotlight attach
        # Record/Play lead the Recording section.
        first = next(i for i, r in enumerate(rows) if "Recording" in r)
        assert "Record an action" in rows[first + 1]
        assert "Review the recording" in rows[first + 2]
        # Panel-scoped keys are listed (read from the panels' BINDINGS).
        assert "── App lens ──" in text
        assert "── Snapshot picker (S) ──" in text
        assert "PDF report" in text
        await pilot.press("escape")


# --------------------------------------------------------------------------
# log hygiene
# --------------------------------------------------------------------------


def test_activity_log_drops_cross_channel_duplicates(monkeypatch) -> None:
    from sandroid.tui.widgets.activity_log import ActivityLog

    log = ActivityLog()
    written: list[str] = []
    monkeypatch.setattr(log, "write", lambda content, **_: written.append(content))
    monkeypatch.setattr(
        log,
        "_get_theme_colors",
        lambda: dict.fromkeys(
            ("text_muted", "primary", "info", "warning", "error", "success"), "white"
        ),
    )
    log.log_message("[*] libssl.so found & will be hooked", "FriTap")
    log.log_message("libssl.so found & will be hooked", "FriTap")
    log.log_info("libssl.so found & will be hooked")
    log.log_info("Reading filesystem timestamps")
    assert len(written) == 2

    log._recent.clear()  # outside the window it is shown again
    log.log_info("Reading filesystem timestamps")
    assert len(written) == 3


@pytest.mark.parametrize(
    ("message", "level", "shown"),
    [
        ("Using specified device: emulator-5558", 20, False),
        ("adbd is running as root", 20, False),
        ("Spawned de.fkie.ground_truth with PID 2407", 20, False),
        (
            "Spawned de.fkie.ground_truth with PID 2407 (PAUSED - will resume "
            "after hooks load)",
            20,
            False,
        ),
        ("Session detached: reason=device-lost", 30, False),
        ("Session detached: reason=process-terminated", 30, True),
        ("Spawned de.fkie.ground_truth (PID 2407) in paused state", 20, True),
        ("Recording saved: 3 events, 4s", 20, True),
        ("Using specified device: emulator-5558", 40, True),
    ],
)
def test_tui_log_handler_quiets_routine_noise(message, level, shown) -> None:
    import logging

    from sandroid.core.events import EventBus, EventType, TUILoggingHandler

    seen: list[str] = []
    handler = TUILoggingHandler()
    bus = EventBus.get()

    def _on(event) -> None:
        seen.append(event.data["message"])

    bus.subscribe(EventType.LOG_MESSAGE, _on)
    try:
        record = logging.LogRecord("x", level, __file__, 1, message, None, None)
        handler.emit(record)
    finally:
        bus.unsubscribe(EventType.LOG_MESSAGE, _on)
    assert (message in seen) is shown


def test_get_state_probe_failure_is_not_a_warning(caplog) -> None:
    import logging

    from sandroid.core.adb_utils import log_adb_result

    with caplog.at_level(logging.DEBUG, logger="sandroid.core.adb_utils"):
        log_adb_result(
            "-s emulator-5558 get-state", "", "error: device 'emulator-5558' not found"
        )
        log_adb_result("-s emulator-5558 shell ls", "", "error: device offline")
    levels = [r.levelno for r in caplog.records]
    assert levels == [logging.DEBUG, logging.WARNING]


def test_tool_usage_lists_each_output_file_once() -> None:
    from sandroid.services.tool_usage_service import ToolUsageService

    svc = ToolUsageService()
    svc.mark_used("fritap", files=["a/fritap.log", "a/fritap_output.json"])
    svc.mark_used("fritap", files=["a/fritap.log", "a/fritap_output.json"])
    assert svc.get_files("fritap") == ["a/fritap.log", "a/fritap_output.json"]


# --------------------------------------------------------------------------
# quit cleanup must not kill emulators / the adb server
# --------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, pid: int, name: str, cmd: list[str]) -> None:
        self.pid, self._name, self._cmd = pid, name, cmd

    def name(self) -> str:
        return self._name

    def cmdline(self) -> list[str]:
        return self._cmd


def test_quit_cleanup_keeps_emulator_and_adb_server(monkeypatch) -> None:
    import psutil

    from sandroid.core.background_tracker import BackgroundWorkTracker

    children = [
        _FakeProc(10, "emulator", ["emulator", "-avd", "Pixel_6_Pro_API_31"]),
        _FakeProc(11, "qemu-system-aarch64", ["qemu-system-aarch64", "-avd", "x"]),
        _FakeProc(12, "adb", ["adb", "-L", "tcp:5037", "fork-server", "server"]),
        _FakeProc(13, "adb", ["adb", "-s", "emulator-5554", "shell", "tcpdump"]),
        _FakeProc(14, "tcpdump", ["tcpdump", "-w", "x.pcap"]),
        _FakeProc(15, "mitmdump", ["mitmdump", "-p", "8080"]),
        _FakeProc(16, "adb", ["adb", "-s", "emulator-5554", "shell", "getevent"]),
    ]

    class _Me:
        def children(self, recursive: bool = False):
            return children

    monkeypatch.setattr(psutil, "Process", lambda *a, **k: _Me())
    found = BackgroundWorkTracker()._detect_untracked_processes()
    pids = {w.identifier for w in found}
    assert pids == {13, 14, 15, 16}


# --------------------------------------------------------------------------
# device name in runs/reports comes from the connected device
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("serial", "name", "model", "expected"),
    [
        ("emulator-5558", "Pixel_6_Pro", "sdk_gphone64_arm64", "Pixel_6_Pro"),
        ("emulator-5558", "emulator-5558", "sdk_gphone64", "sdk_gphone64"),
        ("1A2B3C", "raven", "Pixel 6 Pro", "Pixel_6_Pro"),
        ("1A2B3C", "raven", "", "raven"),
        ("emulator-5554", "", "", None),
    ],
)
def test_resolve_device_name(serial, name, model, expected) -> None:
    from sandroid.core.device import Device
    from sandroid.core.device_manager import resolve_device_name

    device = Device(serial=serial, name=name, model=model)
    assert resolve_device_name(device) == expected


def test_activating_device_records_its_avd_name(monkeypatch) -> None:
    from sandroid.analysis.run_config import _connected_device_name
    from sandroid.core import device_manager as dm_mod
    from sandroid.core.adb import Adb
    from sandroid.core.device import Device
    from sandroid.core.toolbox import Toolbox
    from sandroid.services import get_session_state_service

    def fake_adb(cmd, serial=None):
        if "ro.boot.qemu.avd_name" in cmd:
            return "Pixel_6_Pro\n", ""
        return "", ""

    monkeypatch.setattr(Adb, "send_adb_command", staticmethod(fake_adb))
    monkeypatch.setattr(
        Adb, "get_current_avd_name", staticmethod(lambda serial=None: "WRONG")
    )
    monkeypatch.setattr(Adb, "set_target_device", staticmethod(lambda serial: None))
    monkeypatch.setattr(
        Toolbox, "update_frida_device_serial", staticmethod(lambda s: None)
    )
    monkeypatch.setattr(Toolbox, "switch_device_folder", staticmethod(lambda n: None))
    monkeypatch.setattr(dm_mod, "_active_device_name", None)
    monkeypatch.setattr(dm_mod, "_configured_device_name", None)
    state = get_session_state_service()
    monkeypatch.setattr(state, "_device_name", "Pixel_6_Pro_API_31")

    manager = dm_mod.DeviceManager()
    dev = Device(serial="emulator-5558", name="sdk_gphone64_arm64", state="device")
    manager._devices = {"emulator-5558": dev}
    assert manager.set_active_device("emulator-5558")

    assert dev.name == "Pixel_6_Pro"
    assert state.device_name == "Pixel_6_Pro"
    assert dm_mod.active_device_name() == "Pixel_6_Pro"
    assert _connected_device_name() == "Pixel_6_Pro"


# --------------------------------------------------------------------------
# sandroid-config init without a TTY
# --------------------------------------------------------------------------


@pytest.mark.parametrize("args", [[], ["--yes"]])
def test_config_init_runs_without_tty(tmp_path, args) -> None:
    from click.testing import CliRunner

    from sandroid.config.cli import main

    out = tmp_path / "sandroid.toml"
    # CliRunner's stdin is not a TTY and is empty: any prompt would hit EOF.
    result = CliRunner().invoke(main, ["init", "-o", str(out), *args], input="")
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert "Configuration created successfully" in result.output
    assert "sandroid -i" not in result.output


# --------------------------------------------------------------------------
# Phase-4 UX fixes: quit keys, save-slot fallback, view-switch focus
# --------------------------------------------------------------------------


async def test_q_goes_through_request_quit(monkeypatch) -> None:
    """``q`` must behave like Ctrl+C (QuitController), not hard-exit."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        calls = []
        monkeypatch.setattr(
            app._quit_controller, "request_quit", lambda: calls.append("q")
        )
        await pilot.press("q")
        await settle(pilot)
        assert calls == ["q"]
        assert app.is_running
        assert app.return_code is None


async def test_palette_quit_goes_through_request_quit(monkeypatch) -> None:
    import gc
    import warnings

    from sandroid.tui.screens.command_palette import CommandPalette

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        calls = []
        monkeypatch.setattr(
            app._quit_controller, "request_quit", lambda: calls.append("palette")
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            app.on_command_palette_action_selected(
                CommandPalette.ActionSelected("quit")
            )
            gc.collect()
            await settle(pilot)
        assert calls == ["palette"]
        assert not [w for w in caught if "never awaited" in str(w.message)]


async def test_palette_shows_no_key_the_tui_does_not_bind(monkeypatch) -> None:
    """The palette listed "Pull spotlight DB file" under Space (starts the app);
    v / u (remove / pull spotlight files) do nothing globally either. The
    palette lists them without a key and still runs them by name.
    """
    from textual.widgets import Input

    from sandroid.core.menu_controller import TUI_UNBOUND_KEY_ACTIONS
    from sandroid.tui.screens.command_palette import CommandPalette

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        from sandroid.core.menu_controller import MenuController

        ran: list[str] = []
        monkeypatch.setattr(ms, "execute_action", ran.append)
        # No spotlight app here: let the command count as available.
        monkeypatch.setattr(
            MenuController.get(), "validate_action", lambda *a, **k: (True, "")
        )
        await pilot.press("ctrl+shift+p")
        await settle(pilot)
        palette = app.screen
        assert isinstance(palette, CommandPalette)
        palette.query_one("#palette-input", Input).value = "spotlight DB"
        await settle(pilot)
        text = str(palette.query_one("#palette-results").render())
        line = next(ln for ln in text.splitlines() if "Pull spotlight DB file" in ln)
        assert "Space" not in line
        for name in ("Remove spotlight file", "Pull spotlight files"):
            palette.query_one("#palette-input", Input).value = name
            await settle(pilot)
            text = str(palette.query_one("#palette-results").render())
            row = next(ln for ln in text.splitlines() if name in ln)
            assert "[    v]" not in row
            assert "[    u]" not in row
        # A space typed into the search does not match the " " key.
        palette.query_one("#palette-input", Input).value = "pull spotlight db"
        await settle(pilot)
        await pilot.press("enter")
        await settle(pilot)
        assert ran == ["pull_spotlight_db"]
    assert {"pull_spotlight_db", "remove_file", "pull_files"} == set(
        TUI_UNBOUND_KEY_ACTIONS
    )


async def test_quit_command_uses_tui_quit_path() -> None:
    from sandroid.commands.base import CommandContext
    from sandroid.commands.system_commands import QuitCommand

    called = []

    class _App:
        def action_request_quit(self):
            called.append(True)

        def call_from_thread(self, fn):
            return fn()

    result = await QuitCommand().execute(CommandContext(app=_App()))
    assert called == [True]
    assert result.success
    assert "Exiting" not in result.message

    headless = await QuitCommand().execute(CommandContext())
    assert not headless.success
    assert "q" in headless.message


def test_app_bindings_have_no_duplicate_keys() -> None:
    from sandroid.tui.app import SandroidTUI

    keys = [b.key for b in SandroidTUI.BINDINGS]
    dupes = {k for k in keys if keys.count(k) > 1}
    assert not dupes, dupes
    by_id = {b.id: b for b in SandroidTUI.BINDINGS if b.id}
    assert by_id["show_snapshots"].key == "S"
    assert "pick_save_slot" not in by_id
    assert not any(i.startswith("load_slot_") for i in by_id)
    lenses = ("app", "network", "files", "runs", "timeline")
    assert [by_id[f"lens_{n}"].key for n in lenses] == ["1", "2", "3", "4", "5"]
    # Labels (session timeline) and Tracking: App keys with ids (rebindable).
    assert {
        name: by_id[name].key
        for name in (
            "label_start",
            "label_sub",
            "label_stop",
            "label_point",
            "tracking_toggle",
        )
    } == {
        "label_start": "number_sign",
        "label_sub": "plus",
        "label_stop": "minus",
        "label_point": "B",
        "tracking_toggle": "ctrl+t",
    }
    # ``t`` (TrigDroid's bypass wrapper) is retired: free, and its old id is
    # ignored when it lingers in a user's keybindings.
    assert "t" not in keys
    assert "trigdroid" not in by_id
    from sandroid.tui.app import effective_keymap

    assert effective_keymap({"trigdroid": "t"}) == {}


def test_bypass_chord_digits_never_clash() -> None:
    """``b`` then ``6`` is Emulator; no chord key is bound twice."""
    from sandroid.tui.widgets.spotlight_panel import BypassChordModal, SpotlightPanel

    chord = [b.key for b in BypassChordModal.BINDINGS]
    assert len(chord) == len(set(chord)), chord
    actions = {b.key: b.action for b in BypassChordModal.BINDINGS}
    assert [k for k in chord if k.isdigit()] == ["1", "2", "3", "4", "5", "6"]
    assert actions["6"] == "pick('emulator')"
    # The chord is reached via the panel's own ``b``; ``t`` stays unbound there.
    panel = [b.key for b in SpotlightPanel.BINDINGS]
    assert "b" in panel
    assert "t" not in panel


async def test_picker_s_then_digit_saves_slot(monkeypatch) -> None:
    """Terminal-safe fallback for Ctrl+1-8: S opens the picker, s then a digit."""
    from sandroid.tui.modals import SnapshotPickerModal, SnapshotSlotPickerModal
    from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel

    saves = []
    monkeypatch.setattr(SnapshotsPanel, "save_slot", lambda self, s: saves.append(s))
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        await pilot.press("S")
        await settle(pilot)
        assert isinstance(app.screen, SnapshotPickerModal)
        await pilot.press("s")
        await settle(pilot)
        assert isinstance(app.screen, SnapshotSlotPickerModal)
        await pilot.press("3")
        await settle(pilot)
        assert isinstance(app.screen, SnapshotPickerModal)
        assert saves == ["3"]

        # Esc cancels without saving, a second Esc closes the picker.
        await pilot.press("s")
        await settle(pilot)
        await pilot.press("escape")
        await settle(pilot)
        assert saves == ["3"]
        await pilot.press("escape")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"

        # Ctrl+digit saves through the picker (opened on demand).
        app.action_save_slot("5")
        await settle(pilot)
        assert isinstance(app.screen, SnapshotPickerModal)
        assert saves == ["3", "5"]


async def test_view_switch_never_leaves_focus_in_text_input(monkeypatch) -> None:
    """Switching to the Files lens must not land in its inline input.

    Simulates focus being re-homed into the input during the switch (what
    the phase-4 demo hit); a following ``P`` would be typed into the field.
    """
    from textual.widgets import Input

    from sandroid.tui.widgets.files_panel import FilesPanel

    def _focus_input(self, scroll_visible=True):
        field = self.query_one("#files-input", Input)
        field.set_class(True, "-shown")
        field.focus(scroll_visible)
        return self

    monkeypatch.setattr(FilesPanel, "focus", _focus_input)
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        app.screen.open_files_tab()
        await settle(pilot)
        assert app.screen.active_lens == "files"
        assert not isinstance(app.focused, Input)
        assert app.screen.query_one("#files-panel") in (app.focused.ancestors_with_self)
        await pilot.press("P")
        await settle(pilot)
        assert app.screen.query_one("#files-input", Input).value == ""


async def test_shift_arrows_work_with_nothing_focused() -> None:
    """After Esc leaves an input, focus is None -- navigation must still work."""
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        app.screen.set_focus(None)
        await settle(pilot)
        before = app.screen.query_one("#lens-body").current
        await pilot.press("shift+right")
        await settle(pilot)
        after = app.screen.query_one("#lens-body").current
        assert after != before
        assert app.focused is not None


def test_alt_screen_is_left_once_so_the_summary_stays(monkeypatch, capsys) -> None:
    """NEW-3: the atexit reset sent ``ESC[?1049l`` again after the session
    summary; that restores the cursor saved at startup, and the shell prompt
    then overwrote the summary.
    """
    from sandroid.tui import terminal_reset

    monkeypatch.setitem(terminal_reset._alt_screen_left, "done", False)
    terminal_reset._write_reset_sequences()  # right after app.run() returned
    first = capsys.readouterr().out
    print("═══ Sandroid Session Complete ═══")
    terminal_reset._write_reset_sequences()  # atexit
    second = capsys.readouterr().out
    assert first.count("\x1b[?1049l") == 1
    assert "\x1b[?1049l" not in second
    assert "\x1b[?1000l" in second  # mouse tracking still switched off
    assert "\x1b[?25h" in second


def test_importing_tui_app_emits_no_terminal_reset(tmp_path) -> None:
    """Importing the TUI module (headless runs) must not reset the terminal."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-c", "import sandroid.tui.app"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "\x1b[?1049l" not in proc.stdout
    assert "stty" not in proc.stderr


# ---------------------------------------------------------------------------
# Phase 5 N3: a rejected snapshot create/load must not toast success
# ---------------------------------------------------------------------------


def _snapshot_panel(monkeypatch, ok):
    """Bare SnapshotsPanel whose dialogs answer at once and work runs inline."""
    from types import SimpleNamespace

    from sandroid.tui.widgets import snapshots_panel as sp

    calls: list[tuple[str, str]] = []
    toolbox = SimpleNamespace(
        create_snapshot=lambda name: calls.append(("create", name)) or ok,
        load_snapshot=lambda name: calls.append(("load", name)) or ok,
    )
    answers = {"InputModal": "p5_snap", "ConfirmModal": True}
    fake_app = SimpleNamespace(
        push_screen=lambda screen, cb: cb(answers[type(screen).__name__])
    )
    results: list[tuple[bool, str]] = []
    notes: list[tuple[str, str]] = []
    panel = sp.SnapshotsPanel()
    monkeypatch.setattr(sp.SnapshotsPanel, "app", property(lambda self: fake_app))
    monkeypatch.setattr(panel, "_require_emulator", lambda: True)
    monkeypatch.setattr(panel, "_toolbox", lambda: toolbox)
    monkeypatch.setattr(panel, "_highlighted_tag", lambda: "p5_snap")
    monkeypatch.setattr(panel, "_slot_map", lambda: {"3": "slot-3"})
    monkeypatch.setattr(panel, "_write_slot", lambda slot, tag: None)
    monkeypatch.setattr(
        panel, "_notify", lambda m, s="information": notes.append((m, s))
    )
    monkeypatch.setattr(
        panel,
        "_run_action_bg",
        lambda work, label, refresh_after=False: results.append(work()),
    )
    return panel, answers, calls, results, notes


@pytest.mark.parametrize("ok", [True, False])
def test_snapshot_create_and_load_report_the_service_result(monkeypatch, ok):
    panel, _answers, calls, results, _notes = _snapshot_panel(monkeypatch, ok)
    panel.action_create()
    panel.action_load()
    panel.load_slot("3")
    panel._do_save("slot-3", "3")
    assert [c[0] for c in calls] == ["create", "load", "load", "create"]
    assert [r[0] for r in results] == [ok] * 4
    if not ok:
        assert results[0][1].startswith("Could not create snapshot 'p5_snap'")
        assert results[1][1].startswith("Could not load 'p5_snap'")


def test_snapshot_create_rejects_an_invalid_name_before_adb(monkeypatch):
    panel, answers, calls, results, notes = _snapshot_panel(monkeypatch, True)
    answers["InputModal"] = "bad name;touch /tmp/x"
    panel.action_create()
    assert calls == []
    assert results == []
    assert notes
    assert notes[-1][1] == "error"
    assert "invalid snapshot name" in notes[-1][0]


# ---------------------------------------------------------------------------
# Phase 5 N1(b): hint when recording starts in the open app without a reset
# ---------------------------------------------------------------------------


def test_key_labels_are_words_in_both_styles() -> None:
    """No key glyphs in the footer (compact) or help/palette (long) labels."""
    from sandroid.tui.key_display import KEY_WORDS, format_key, key_words

    keys = [
        "up",
        "down",
        "left",
        "right",
        "shift+left",
        "enter",
        "tab",
        "backspace",
        "alt+x",
        "R",
        "ctrl+shift+up",
    ]
    for style in ("compact", "long"):
        for key in keys:
            label = format_key(key, style)
            assert not set(KEY_WORDS) & set(label), (style, key, label)
    assert key_words("⇧R ⏎ ←/→") == "Shift+R Enter Left/Right"


async def test_header_breadcrumb_uses_plain_separators() -> None:
    """``Sandroid / device / app   snapshot name``: no ○ ▸ ◇ glyphs."""
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.lens_shell import ShellHeader

    app = SandroidTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await boot(app, pilot)
        header = app.screen.query_one(ShellHeader)
        header._crumb = "emulator-5554  [dim]/[/dim]  [b]com.example[/b]"
        header._snapshot = "clean"
        title = str(header.format_title())
        assert not set("○▸◇") & set(title), title
        assert "Sandroid" in title
        assert "snapshot clean" in title
