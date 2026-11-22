"""The live device screen column (Ctrl+G) and its widget.

Pilot tests run against a fake service (no grpc, no device) with a fixed
cell size; headless Textual never runs ``App._display``, so the graphics
path (iTerm2 / kitty / sixel) is covered by unit tests of the encoders, the
geometry and the bezel, plus a guard test for the Textual private parts the
paint hooks rely on.
"""

from __future__ import annotations

import base64
import inspect
import io
import json
import re
import threading
import time
from types import SimpleNamespace

import numpy as np
import pytest
from PIL import Image
from pilot_helpers import boot, settle, until
from textual.geometry import Region

from sandroid.services.device_screen_service import ScreenFrame, ScreenState
from sandroid.tui import terminal_graphics
from sandroid.tui.screens.main_screen import (
    DEVICE_CHROME_COLS,
    DEVICE_CHROME_ROWS,
    DEVICE_MIN_COLS,
    LENS_MIN_COLS,
    MainScreen,
    focus_takes_text,
    inspector_cols,
)
from sandroid.tui.widgets import device_screen as ds
from sandroid.tui.widgets.device_screen import (
    Bezel,
    DeviceScreen,
    Geometry,
    encode_iterm,
    encode_kitty,
    encode_sixel,
    halfblock_strips,
    preferred_cols,
)
from sandroid.tui.widgets.lens_shell import InspectorContent, is_shown

SIZE = (200, 50)
CELL = (8.0, 16.0)
TABS = [("Summary", [("", "1")]), ("Diff", [("", "2")]), ("Events", [("", "3")])]


# --------------------------------------------------------------------------
# fakes + fixtures
# --------------------------------------------------------------------------


class FakeService:
    """Records every call; refuses input like the real service would."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.sink = None
        self.visible: tuple[bool, tuple[int, int]] | None = None
        self.locked: str | None = None
        self.allow_clipboard = True
        self.closed = False

    @property
    def state(self) -> ScreenState:
        return ScreenState.OFF

    @property
    def serial(self) -> str | None:
        return None

    def attach(self, sink) -> None:
        self.sink = sink
        self.calls.append(("attach", sink is not None))

    def set_visible(self, visible: bool, panel_px: tuple[int, int]) -> None:
        self.visible = (visible, panel_px)
        self.calls.append(("visible", visible, panel_px))

    def set_input_policy(self, *, locked: str | None, allow_clipboard: bool) -> None:
        self.locked, self.allow_clipboard = locked, allow_clipboard
        self.calls.append(("policy", locked, allow_clipboard))

    def touch(self, action: str, x: int, y: int) -> str | None:
        if self.locked:
            return self.locked
        self.calls.append(("touch", action, x, y))
        return None

    def wheel(self, x: int, y: int, dy: int) -> str | None:
        if self.locked:
            return self.locked
        self.calls.append(("wheel", x, y, dy))
        return None

    def key(self, name: str) -> str | None:
        if self.locked:
            return self.locked
        self.calls.append(("key", name))
        return None

    def text(self, text: str) -> str | None:
        if self.locked:
            return self.locked
        self.calls.append(("text", text))
        return None

    def paste(self, text: str) -> str | None:
        if self.locked:
            return self.locked
        if not self.allow_clipboard:
            return "pasting is off while Tracking or Record runs"
        self.calls.append(("paste", text))
        return None

    def lift(self) -> None:
        self.calls.append(("lift",))

    def close(self) -> None:
        self.closed = True

    def of(self, kind: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == kind]


@pytest.fixture(autouse=True)
def _private_config_home(tmp_path, monkeypatch):
    """Own config dir per test (ui_state lives there); no detection cache."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    terminal_graphics.set_result(None)
    yield
    terminal_graphics.set_result(None)


@pytest.fixture
def fake(monkeypatch) -> FakeService:
    """The fake service, injected where MainScreen gets the real one."""
    from sandroid import services

    service = FakeService()
    monkeypatch.setattr(services, "get_device_screen_service", lambda: service)
    monkeypatch.setattr(MainScreen, "device_cell_px", CELL)
    return service


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _col(ms):
    return ms.query_one("#device-col")


def _dev(ms) -> DeviceScreen:
    return ms.query_one("#device-screen", DeviceScreen)


async def _open(pilot, ms) -> DeviceScreen:
    await pilot.press("ctrl+g")
    await until(pilot, lambda: ms.device_is_open and ms.device_widget is not None)
    dev = ms.device_widget
    await until(pilot, lambda: dev.geometry is not None)
    await settle(pilot)
    return dev


def _cell_of(dev: DeviceScreen, ux: float, uy: float) -> tuple[int, int]:
    """Widget offset of the cell at ``(ux, uy)`` (0..1) of the phone screen."""
    g = dev.geometry
    assert g is not None
    assert g.halfblock
    px = g.img_off_x + ux * g.img_w
    py = g.img_off_y + uy * g.img_h
    return int(g.box_x + px), int(g.box_y + py / 2)


def _expected(dev: DeviceScreen, offset: tuple[int, int]) -> tuple[int, int, bool]:
    region = dev.content_region
    sx = dev.region.x + offset[0] + 0.5
    sy = dev.region.y + offset[1] + 0.5
    x, y, inside = dev.geometry.to_device(sx - region.x, sy - region.y)
    return int(x), int(y), inside


def _frame(w: int, h: int, gen: int = 1, color=(10, 200, 30)) -> ScreenFrame:
    pixels = np.zeros((h, w, 3), np.uint8)
    pixels[:] = color
    return ScreenFrame(pixels, w, h, 0, time.monotonic(), gen)


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------


def test_toggle_device_is_a_palette_and_keymap_action() -> None:
    from sandroid.core.menu_controller import ActionCategory, MenuController
    from sandroid.tui.app import _MAIN_SCREEN_ONLY, SandroidTUI

    MenuController.reset()
    action = MenuController.get().get_action_by_name("toggle_device")
    assert action is not None
    assert action.category is ActionCategory.NAVIGATION
    assert action.key == "ctrl+g"
    assert action.inline_text == "[^G] Device screen"
    ids = {b.id: b.key for b in SandroidTUI.BINDINGS if b.id}
    assert ids["toggle_device"] == "ctrl+g"
    assert "toggle_device" in _MAIN_SCREEN_ONLY
    # Ctrl+G is used by nothing else.
    keys = [b.key for b in SandroidTUI.BINDINGS]
    assert keys.count("ctrl+g") == 1


def test_menu_controller_leaves_toggle_device_to_the_view_layer() -> None:
    from sandroid.core.menu_controller import MenuController

    MenuController.reset()
    queue = SimpleNamespace(parse_interactive_char=pytest.fail)
    assert MenuController.get().execute_action("toggle_device", queue) is True


def test_ctrl_g_is_not_bound_by_focusable_widgets() -> None:
    from textual.widgets import DataTable, Input, OptionList, RichLog, TextArea

    for cls in (Input, TextArea, DataTable, OptionList, RichLog, DeviceScreen):
        assert all(b.key != "ctrl+g" for b in cls.BINDINGS), cls


def test_focus_takes_text() -> None:
    from textual.widgets import Input, Static

    assert focus_takes_text(Input())
    assert focus_takes_text(DeviceScreen(None, cell_px=CELL))
    assert not focus_takes_text(Static())
    assert not focus_takes_text(None)


def test_inspector_cols_follow_the_side_slot_css() -> None:
    assert inspector_cols(200) == 80
    assert inspector_cols(130) == 56  # min-width 56
    assert inspector_cols(110) == 49  # -narrow: 45 %


# --------------------------------------------------------------------------
# Textual private parts (guard)
# --------------------------------------------------------------------------


def test_textual_private_parts_the_paint_hooks_use() -> None:
    from textual.app import App
    from textual.driver import Driver

    from sandroid.tui.app import SandroidTUI

    assert list(inspect.signature(App._display).parameters) == [
        "self",
        "screen",
        "renderable",
    ]
    assert list(inspect.signature(SandroidTUI._display).parameters) == [
        "self",
        "screen",
        "renderable",
    ]
    for name in ("_begin_update", "_end_update", "_driver", "_sync_available"):
        assert hasattr(App, name) or name in App.__init__.__code__.co_names, name
    assert callable(Driver.process_message)
    assert terminal_graphics.textual_supports_graphics()
    # _end_update is called inside _display (the hook's position).
    assert "self._end_update()" in inspect.getsource(App._display)
    # The writer queue the frame drop looks at.
    from textual.drivers._writer_thread import WriterThread

    assert "_queue" in inspect.getsource(WriterThread.__init__)


async def test_end_update_runs_the_registered_device_screen(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        await boot(app, pilot)
        seen: list[object] = []
        widget = SimpleNamespace(_after_textual_paint=seen.append, _last_error="")
        app._device_screen_ref = lambda: widget
        app._device_paint_update = "update"
        app._end_update()
        assert seen == ["update"]
        app._device_screen_ref = None


# --------------------------------------------------------------------------
# open / focus / close
# --------------------------------------------------------------------------


async def test_ctrl_g_opens_focuses_and_closes(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        col = _col(ms)
        # Lazy: nothing is mounted (and no service exists) before Ctrl+G.
        assert not col.children
        assert not is_shown(col)
        assert fake.calls == []

        dev = await _open(pilot, ms)
        assert is_shown(col)
        assert ms.focused is dev
        assert ms.has_class("-device-open")
        assert fake.sink is dev
        await until(pilot, lambda: fake.visible and fake.visible[0])
        assert fake.visible[1] == dev.geometry.stream_px

        await pilot.press("escape")  # focus back to the lens, stays open
        await settle(pilot)
        assert ms.device_is_open
        assert ms.focused is not dev
        assert ms.focused is ms.lens_widget() or ms.lens_widget() in (
            ms.focused.ancestors
        )

        await pilot.press("ctrl+g")  # open, not focused -> focus it
        await settle(pilot)
        assert ms.device_is_open
        assert ms.focused is dev

        await pilot.press("ctrl+g")  # focused -> close
        await settle(pilot)
        assert not ms.device_is_open
        assert not is_shown(col)
        assert not ms.has_class("-device-open")
        assert ms.focused is not dev
        await until(pilot, lambda: fake.visible == (False, (0, 0)))
        assert fake.of("lift")


async def test_controls_and_status_line(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        words = [w.key_name for w in ms.query(ds.DeviceKeyWord)]
        assert words == ["GoBack", "GoHome", "AppSwitch"]
        assert str(ms.query_one("#device-keys").query_one(".device-key").render())
        status = ms.query_one("#device-status", ds.DeviceStatus)
        assert str(status.render()) == "off"
        dev.set_state(ScreenState.GONE, "killed")
        await until(pilot, lambda: str(status.render()) == "emulator gone")
        dev.set_state(ScreenState.NO_EXTRA, "")
        await until(pilot, lambda: str(status.render()) == "install sandroid[screen]")
        dev.set_state(ScreenState.LIVE, "")
        await until(pilot, lambda: str(status.render()) == "live")
        dev.stats["fps"] = 0.0
        dev._fps_frames = 30
        dev._fps_t0 = time.monotonic() - 1.0
        dev._tick_status()
        assert re.fullmatch(r"live · \d+ fps", str(status.render()))

        # A click on a word sends its key without taking the focus.
        await pilot.press("escape")
        await settle(pilot)
        focused = ms.focused
        home = [w for w in ms.query(ds.DeviceKeyWord) if w.key_name == "GoHome"][0]
        await pilot.click(home)
        await settle(pilot)
        assert ("key", "GoHome") in fake.calls
        assert ms.focused is focused


async def test_palette_pick_toggles_the_column(fake) -> None:
    from sandroid.tui.screens.command_palette import CommandPalette

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        app.on_command_palette_action_selected(
            CommandPalette.ActionSelected("toggle_device")
        )
        await until(pilot, lambda: ms.device_is_open)
        await until(pilot, lambda: ms.device_has_focus)
        app.on_command_palette_action_selected(
            CommandPalette.ActionSelected("toggle_device")
        )
        await until(pilot, lambda: not ms.device_is_open)


async def test_open_state_is_remembered_and_restored(fake) -> None:
    from sandroid.config.ui_state import load_ui_state

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await _open(pilot, ms)
        await until(
            pilot, lambda: load_ui_state().get("device_screen") == {"open": True}
        )
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await until(pilot, lambda: ms.device_is_open and is_shown(_col(ms)))
        # Restored without the focus: keys stay with the lens.
        assert ms.focused is not ms.device_widget
        await pilot.press("ctrl+g")
        await settle(pilot)
        await pilot.press("ctrl+g")
        await until(
            pilot, lambda: load_ui_state().get("device_screen") == {"open": False}
        )


# --------------------------------------------------------------------------
# width fit
# --------------------------------------------------------------------------


def _want(ms) -> int:
    height = ms.query_one("#workspace").size.height
    return ms.device_widget.preferred_cols(height - DEVICE_CHROME_ROWS) + (
        DEVICE_CHROME_COLS
    )


async def test_inspector_and_device_side_by_side_keep_the_lens(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        ms.open_inspector(InspectorContent(title="t", tabs=TABS))
        await settle(pilot)
        await _open(pilot, ms)
        col, slot, left = (
            _col(ms),
            ms.query_one("#side-slot"),
            ms.query_one("#left-col"),
        )
        assert ms.inspector_is_open
        assert ms.device_is_open
        assert is_shown(col)
        assert is_shown(slot)
        assert col.outer_size.width == _want(ms)  # room enough: the phone's width
        assert slot.outer_size.width == inspector_cols(SIZE[0])
        assert left.outer_size.width >= LENS_MIN_COLS
        assert slot.region.right <= col.region.x  # Inspector, then the phone


async def test_narrow_window_shrinks_the_phone_then_a_column_yields(
    fake, monkeypatch
) -> None:
    monkeypatch.setattr(MainScreen, "device_cell_px", (5.0, 16.0))  # wide phone
    app = _app()
    async with app.run_test(size=(120, 40)) as pilot:
        ms = await boot(app, pilot)
        ms.open_inspector(InspectorContent(title="t", tabs=TABS))
        await settle(pilot)
        await _open(pilot, ms)
        col, left = _col(ms), ms.query_one("#left-col")
        limit = 120 - inspector_cols(120) - LENS_MIN_COLS
        assert _want(ms) > limit  # the phone would like more ...
        assert col.outer_size.width == limit  # ... and shrinks
        assert ms.inspector_is_open
        assert left.outer_size.width >= LENS_MIN_COLS

        # Narrower: the phone would get < 20 columns; the Inspector (opened
        # first) yields, with one log line.
        await pilot.resize_terminal(100, 40)
        await until(pilot, lambda: not ms.inspector_is_open)
        assert ms.device_is_open
        await until(pilot, lambda: col.outer_size.width == min(_want(ms), 60))
        assert ms.query_one("#left-col").outer_size.width >= LENS_MIN_COLS

        # Opening the Inspector now closes the device column instead.
        ms.open_inspector(InspectorContent(title="t", tabs=TABS))
        await settle(pilot)
        assert ms.inspector_is_open
        assert not ms.device_is_open
        assert 100 - inspector_cols(100) - LENS_MIN_COLS - 2 < DEVICE_MIN_COLS


async def test_column_refits_when_the_log_drawer_opens(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await _open(pilot, ms)
        col = _col(ms)
        before = col.outer_size.width
        await pilot.press("escape")  # the lens has the focus
        await settle(pilot)
        await pilot.press("grave_accent")
        await until(pilot, lambda: ms.log_drawer_is_open)
        await until(pilot, lambda: col.outer_size.width < before)
        assert col.outer_size.width == _want(ms)


async def test_rotation_refits_the_column(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        col = _col(ms)
        portrait = col.outer_size.width
        dev.set_device_size(2400, 1080, 1)  # landscape, from the stream thread
        await until(pilot, lambda: col.outer_size.width > portrait)
        assert col.outer_size.width <= int(SIZE[0] * 0.6)


# --------------------------------------------------------------------------
# keys and focus
# --------------------------------------------------------------------------


async def test_focused_device_takes_d_question_mark_and_arrows(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        ms.open_inspector(InspectorContent(title="t", tabs=TABS))
        await settle(pilot)
        inspector = ms.query_one("#inspector")
        tab = inspector.tab_index
        dev = await _open(pilot, ms)
        assert ms.focused is dev
        await pilot.press("D", "question_mark", "left", "right", "r", "f2", "f3")
        await settle(pilot)
        assert type(app.screen).__name__ == "MainScreen"  # no Devices, no Help
        assert inspector.tab_index == tab
        assert ("text", "D") in fake.calls
        assert ("text", "?") in fake.calls
        assert ("text", "r") in fake.calls  # not Record
        assert ("key", "ArrowLeft") in fake.calls
        assert ("key", "ArrowRight") in fake.calls
        assert ("key", "GoHome") in fake.calls
        assert ("key", "AppSwitch") in fake.calls
        assert ms.focused is dev

        # Unfocused, the same keys keep their usual meaning.
        await pilot.press("escape")
        await settle(pilot)
        await pilot.press("right")
        await until(pilot, lambda: inspector.tab_index == (tab + 1) % 3)


async def test_typing_guard_does_not_swallow_keys_for_the_phone(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await _open(pilot, ms)
        ms.start_typing_guard()
        await pilot.press("a")
        await settle(pilot)
        assert ("text", "a") in fake.calls


async def test_paste_goes_to_the_phone_and_is_refused_while_tracking(
    fake, monkeypatch
) -> None:
    from textual import events

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        dev.post_message(events.Paste("hello"))
        await until(pilot, lambda: ("paste", "hello") in fake.calls)

        monkeypatch.setattr(MainScreen, "_device_input_policy", lambda s: (None, False))
        dev.post_message(events.Paste("secret"))
        status = ms.query_one("#device-status")
        await until(pilot, lambda: "pasting is off" in str(status.render()))
        assert status.has_class("-hint")
        assert ("paste", "secret") not in fake.calls
        assert fake.allow_clipboard is False


# --------------------------------------------------------------------------
# mouse
# --------------------------------------------------------------------------


async def test_unfocused_click_sends_down_up_without_focus(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        await pilot.press("escape")
        await settle(pilot)
        focused = ms.focused
        assert focused is not dev
        offset = _cell_of(dev, 0.5, 0.3)
        x, y, inside = _expected(dev, offset)
        assert inside
        await pilot.click(dev, offset=offset)
        await settle(pilot)
        assert ms.focused is focused  # the mouse never takes the focus
        assert fake.of("touch") == [("touch", "down", x, y), ("touch", "up", x, y)]
        # Device px of the current orientation, inside the device.
        assert 0 <= x < dev.dev_w
        assert 0 <= y < dev.dev_h
        assert abs(x - dev.dev_w * 0.5) < dev.dev_w * 0.06
        assert abs(y - dev.dev_h * 0.3) < dev.dev_h * 0.06


async def test_click_on_the_bezel_is_ignored(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        g = dev.geometry
        assert g.box_x >= 0
        # The bezel's first column (1 px border in half-block) and a point
        # outside the phone box.
        for offset in ((g.box_x, g.box_y + 5), (0, 0)):
            assert not _expected(dev, offset)[2]
            await pilot.click(dev, offset=offset)
            await settle(pilot)
        assert fake.of("touch") == []


async def test_drag_leaving_the_column_still_sends_up(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        start = _cell_of(dev, 0.5, 0.5)
        await pilot.mouse_down(dev, offset=start)
        await settle(pilot)
        lens = ms.query_one("#lens-host")
        await pilot.hover(lens, offset=(5, 5))
        await settle(pilot)
        await pilot.mouse_up(lens, offset=(5, 5))
        await settle(pilot)
        touches = fake.of("touch")
        assert touches[0][1] == "down"
        assert touches[-1][1] == "up"
        # Clamped to the screen's left edge while outside.
        assert touches[-1][2] == 0
        assert app.mouse_captured is None


async def test_wheel_is_forwarded(fake) -> None:
    from textual import events

    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        ox, oy = _cell_of(dev, 0.5, 0.5)
        region = dev.region
        event = events.MouseScrollDown(
            dev, ox, oy, 0, 0, 0, False, False, False, region.x + ox, region.y + oy
        )
        dev.post_message(event)
        await until(pilot, lambda: fake.of("wheel"))
        assert fake.of("wheel")[0][3] == 1


async def test_input_is_locked_while_replaying(fake, monkeypatch) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        rc = app._recording_controller
        monkeypatch.setattr(type(rc), "is_replaying", property(lambda s: True))
        monkeypatch.setattr(type(rc), "run_kind", property(lambda s: "Rewind"))
        await pilot.click(dev, offset=_cell_of(dev, 0.5, 0.5))
        await settle(pilot)
        assert fake.locked == "input is locked while a rewind runs"
        assert fake.of("touch") == []
        status = ms.query_one("#device-status")
        assert str(status.render()) == "input is locked while a rewind runs"
        monkeypatch.setattr(type(rc), "is_replaying", property(lambda s: False))
        await pilot.click(dev, offset=_cell_of(dev, 0.5, 0.5))
        await settle(pilot)
        assert fake.locked is None
        assert [c[1] for c in fake.of("touch")] == ["down", "up"]


# --------------------------------------------------------------------------
# streaming, frames, overlays
# --------------------------------------------------------------------------


async def test_stream_pauses_under_a_modal(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        await _open(pilot, ms)
        await until(pilot, lambda: fake.visible and fake.visible[0])
        await pilot.press("escape")  # lens focus, so ? opens Help
        await settle(pilot)
        await pilot.press("question_mark")
        await until(pilot, lambda: type(app.screen).__name__ == "HelpScreen")
        await until(pilot, lambda: fake.visible[0] is False)
        await pilot.press("escape")
        await until(pilot, lambda: type(app.screen).__name__ == "MainScreen")
        await until(pilot, lambda: fake.visible[0] is True)


async def test_frames_render_as_half_blocks(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        dev.set_state(ScreenState.LIVE, "")
        w, h = dev.geometry.stream_px
        thread = threading.Thread(target=dev.push_frame, args=(_frame(w, h),))
        thread.start()
        thread.join()
        await until(pilot, lambda: dev._hb_strips is not None)
        row = dev.geometry.box_y + dev.geometry.box_rows // 2
        text = "".join(seg.text for seg in dev.render_line(row))
        assert "▀" in text
        # An older generation (a stream before a device switch) is dropped.
        before = dev.stats["frames_in"]
        dev.push_frame(_frame(w, h, gen=0, color=(1, 2, 3)))
        assert dev.stats["frames_in"] == before
        # The device size comes from each frame: a landscape frame re-fits.
        col = _col(ms)
        width = col.outer_size.width
        dev.push_frame(_frame(2400 // 4, 1080 // 4, gen=2))
        await until(pilot, lambda: (dev.dev_w, dev.dev_h) == (600, 270))
        await until(pilot, lambda: col.outer_size.width > width)
        # Not live any more: the image goes.
        dev.set_state(ScreenState.GONE, "")
        await until(pilot, lambda: dev._hb_strips is None)


async def test_a_toast_does_not_cover_the_phone(fake) -> None:
    from textual.widgets._toast import Toast

    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        ms = await boot(app, pilot)
        ms.open_inspector(InspectorContent(title="t", tabs=TABS))
        await settle(pilot)
        await _open(pilot, ms)
        app.notify("friTap keeps running; nothing changed")
        await until(pilot, lambda: bool(app.screen.query(Toast)))
        await settle(pilot)
        col = _col(ms)
        toasts = list(app.screen.query(Toast))
        assert toasts
        for toast in toasts:
            assert toast.region.width > 0
            assert toast.region.right <= col.region.x, (toast.region, col.region)


async def test_a_toast_does_not_cover_a_column_restored_at_startup(fake) -> None:
    """A column restored from ui_state while MainScreen mounts.

    Found on device: toasts stayed bottom-right and covered the column.
    """
    from textual.widgets._toast import Toast

    from sandroid.config.ui_state import update_ui_state

    update_ui_state("device_screen", {"open": True})
    app = _app()
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        ms = await boot(app, pilot)
        await until(pilot, lambda: ms.device_is_open and is_shown(_col(ms)))
        app.notify("No spotlight app. Press c (use the foreground app) first.")
        await until(pilot, lambda: bool(app.screen.query(Toast)))
        await settle(pilot)
        col = _col(ms)
        toasts = list(app.screen.query(Toast))
        assert toasts
        for toast in toasts:
            assert toast.region.width > 0
            assert toast.region.right <= col.region.x, (toast.region, col.region)


async def test_writer_backlog_drops_new_frames(fake, monkeypatch) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        written: list[str] = []
        monkeypatch.setattr(app._driver, "write", written.append)
        monkeypatch.setattr(app._driver, "flush", lambda: None)
        dev.backend = "iterm"
        dev._payload = (dev._geom_gen, dev.geometry, "IMAGE")
        monkeypatch.setattr(dev, "_writer_backlog", lambda: 30)
        dev._emit(new_frame=True)
        assert dev.stats["drops"] == 1
        assert written == []
        monkeypatch.setattr(dev, "_writer_backlog", lambda: 0)
        dev._ack_ok = True
        dev._emit(new_frame=True)
        assert "".join(written).endswith("IMAGE\x1b[6n\x1b8")
        assert dev._on_ack() is True  # the ack is ours ...
        assert dev._on_ack() is False  # ... and only once
        dev._shown = False
        dev.backend = "halfblock"
        dev._payload = None


async def test_unmount_joins_the_encode_thread(fake) -> None:
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms = await boot(app, pilot)
        dev = await _open(pilot, ms)
        thread = dev._thread
        assert thread is not None
        assert thread.is_alive()
        await dev.remove()
        await settle(pilot)
        assert not thread.is_alive()
        assert fake.sink is None


# --------------------------------------------------------------------------
# encoders, geometry, bezel (the graphics path)
# --------------------------------------------------------------------------


def _gradient(w: int = 24, h: int = 36) -> np.ndarray:
    arr = np.zeros((h, w, 3), np.uint8)
    arr[..., 0] = np.linspace(0, 255, w, dtype=np.uint8)[None, :]
    arr[..., 1] = np.linspace(0, 255, h, dtype=np.uint8)[:, None]
    arr[..., 2] = 128
    return arr


def test_encode_iterm_is_an_inline_jpeg() -> None:
    arr = _gradient()
    data = encode_iterm(arr)
    match = re.match(
        rb"\x1b\]1337;File=inline=1;size=(\d+);width=24px;height=36px;"
        rb"preserveAspectRatio=0;doNotMoveCursor=1:([A-Za-z0-9+/=]+)\x07$",
        data,
    )
    assert match
    jpeg = base64.b64decode(match.group(2))
    assert len(jpeg) == int(match.group(1))
    assert Image.open(io.BytesIO(jpeg)).size == (24, 36)


def test_encode_kitty_chunks_are_quiet_and_replace_one_image() -> None:
    arr = np.random.default_rng(1).integers(0, 255, (80, 80, 3), np.uint8)
    data = encode_kitty(arr)
    chunks = re.findall(rb"\x1b_G([^;]*);([^\x1b]*)\x1b\\", data)
    assert len(chunks) > 1
    first = chunks[0][0]
    assert b"a=T" in first
    assert b"i=4242" in first
    assert b"p=1" in first
    assert b"s=80" in first
    assert b"v=80" in first
    assert b"o=z" in first
    assert all(b"q=2" in ctrl for ctrl, _ in chunks)
    assert chunks[-1][0].endswith(b"m=0")
    assert all(ctrl.endswith(b"m=1") for ctrl, _ in chunks[:-1])
    import zlib

    raw = zlib.decompress(base64.b64decode(b"".join(p for _, p in chunks)))
    assert raw == arr.tobytes()


def test_encode_sixel_has_header_palette_and_bands() -> None:
    arr = _gradient(10, 13)
    data = encode_sixel(arr)
    assert data.startswith(b'\x1bP0;1;0q"1;1;10;13')
    assert data.endswith(b"\x1b\\")
    assert b"#0;2;0;0;0" in data
    assert data.count(b"$-") == 2  # 3 bands of 6 rows for 13 rows


def test_halfblock_strips_cover_the_region() -> None:
    arr = _gradient(6, 8)
    strips = halfblock_strips(arr, 10, 6, 2, 1, (5, 5, 5))
    assert len(strips) == 6
    assert all(s.cell_length == 10 for s in strips)
    assert "▀" not in "".join(seg.text for seg in strips[0])
    assert "".join(seg.text for seg in strips[1]).count("▀") == 6


def test_style_cache_is_a_bounded_lru() -> None:
    info = ds._cell_style.cache_info()
    assert info.maxsize == ds.STYLE_CACHE_MAX


def test_geometry_maps_cells_to_device_px() -> None:
    g = Geometry.compute(Region(0, 0, 40, 30), 8, 16, 1080, 2400, halfblock=True)
    assert g.halfblock
    assert g.bezel == 1
    assert g.box_cols <= 40
    assert g.box_rows <= 30
    cx = g.box_x + g.img_off_x + g.img_w / 2
    cy = g.box_y + (g.img_off_y + g.img_h / 2) / 2
    x, y, inside = g.to_device(cx, cy)
    assert inside
    assert abs(x - 540) < 1080 / g.img_w + 1
    assert abs(y - 1200) < 2400 / g.img_h + 1
    x, y, inside = g.to_device(g.box_x, g.box_y)  # bezel corner
    assert not inside
    assert (x, y) == (0.0, 0.0)
    assert g.stream_px == (g.img_w * 2, g.img_h * 2)


def test_geometry_pixel_backend_with_bezel() -> None:
    g = Geometry.compute(Region(5, 2, 40, 30), 10, 20, 1080, 2400, halfblock=False)
    assert not g.halfblock
    assert g.bezel > 0
    assert g.canvas_w >= g.outer[2]
    assert g.canvas_h >= g.outer[3]
    assert g.img_off_x == g.outer[0] + g.bezel
    assert g.stream_px == (g.img_w, g.img_h)
    assert abs(g.img_w / g.img_h - 1080 / 2400) < 0.01
    sixel = Geometry.compute(
        Region(0, 0, 40, 30), 10, 20, 1080, 2400, halfblock=False, sixel=True
    )
    assert sixel.canvas_h == sixel.outer[3]  # no padding into the next row


def test_preferred_cols_fill_the_height() -> None:
    portrait = preferred_cols(40, CELL, (1080, 2400), halfblock=True)
    landscape = preferred_cols(40, CELL, (2400, 1080), halfblock=True)
    assert landscape > portrait * 3
    g = Geometry.compute(Region(0, 0, portrait, 40), *CELL, 1080, 2400, True)
    assert g.box_rows >= 39  # the phone fills the rows
    assert preferred_cols(1, CELL, (1080, 2400), halfblock=True) == 2


def test_bezel_canvas_and_rounded_screen() -> None:
    g = Geometry.compute(Region(0, 0, 30, 20), 10, 20, 1080, 2400, halfblock=False)
    bz = Bezel(g, (1, 2, 3), True)
    assert bz.canvas.shape == (g.canvas_h, g.canvas_w, 3)
    assert tuple(bz.canvas[0, 0]) == (1, 2, 3)  # outside the body: background
    mid = bz.canvas[g.img_off_y + g.img_h // 2, g.img_off_x + g.img_w // 2]
    assert tuple(mid) == (0, 0, 0)  # the screen is black until a frame comes
    assert len(bz.corners) == 4
    bz.canvas[g.img_off_y : g.img_off_y + g.img_h, g.img_off_x : g.img_off_x + 5] = 255
    bz.mask_corners()
    corner = bz.canvas[g.img_off_y, g.img_off_x]
    assert tuple(corner) != (255, 255, 255)  # the rounded corner masked it
    plain = Bezel(g, (1, 2, 3), False)
    assert plain.corners == []


# --------------------------------------------------------------------------
# terminal_graphics
# --------------------------------------------------------------------------


def test_parse_replies() -> None:
    caps = terminal_graphics.TermGraphics()
    terminal_graphics.parse_replies(
        "\x1b_Gi=31;OK\x1b\\\x1bP>|kitty(0.35)\x1b\\\x1b[6;17;8t\x1b[?62;4;22c",
        caps,
    )
    assert caps.kitty
    assert caps.sixel
    assert caps.xtversion == "kitty(0.35)"
    assert caps.cell_px == (8.0, 17.0)
    assert caps.da1 == [62, 4, 22]


@pytest.mark.parametrize(
    ("caps", "preferred", "backend"),
    [
        ({"iterm": True, "kitty": True}, "auto", "iterm"),
        ({"kitty": True, "sixel": True}, "auto", "kitty"),
        ({"sixel": True}, "auto", "sixel"),
        ({}, "auto", "halfblock"),
        ({"iterm": True, "tmux": True}, "auto", "halfblock"),
        ({"iterm": True}, "halfblock", "halfblock"),
        ({}, "sixel", "sixel"),
    ],
)
def test_choose_backend(caps, preferred, backend) -> None:
    result = terminal_graphics.TermGraphics(**caps)
    terminal_graphics.choose_backend(result, preferred)
    assert result.backend == backend
    assert result.reason


def test_detect_without_query_uses_the_environment(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        terminal_graphics, "query_terminal", lambda q, t=0.2: calls.append(q) or ""
    )
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setenv("TERM_PROGRAM", "iTerm.app")
    caps = terminal_graphics.detect(query=False)
    assert caps.backend == "iterm"
    assert calls == []
    assert terminal_graphics.result() is caps
    monkeypatch.setenv("TMUX", "/tmp/tmux-1/default,1,0")
    assert terminal_graphics.detect().backend == "halfblock"
    assert calls == []  # never queried inside tmux


def test_graphics_reset_only_deletes_kitty_images() -> None:
    terminal_graphics.set_result(terminal_graphics.TermGraphics(backend="iterm"))
    assert terminal_graphics.graphics_reset_sequence() == ""
    terminal_graphics.set_result(terminal_graphics.TermGraphics(backend="kitty"))
    assert terminal_graphics.graphics_reset_sequence() == ds.KITTY_DELETE


def test_current_cell_px_prefers_the_query_while_it_matches(monkeypatch) -> None:
    monkeypatch.setattr(terminal_graphics, "cell_px_from_kernel", lambda: (8.02, 17.1))
    assert terminal_graphics.current_cell_px((8.0, 17.0)) == (8.0, 17.0)
    monkeypatch.setattr(terminal_graphics, "cell_px_from_kernel", lambda: (10.4, 21.2))
    assert terminal_graphics.current_cell_px((8.0, 17.0)) == (10.0, 21.0)
    monkeypatch.setattr(terminal_graphics, "cell_px_from_kernel", lambda: None)
    assert terminal_graphics.current_cell_px(None) == (8.0, 16.0)


def test_ui_state_key_is_plain_json(tmp_path) -> None:
    from sandroid.config.ui_state import load_ui_state, update_ui_state

    path = tmp_path / "s.json"
    update_ui_state("device_screen", {"open": True}, path)
    assert json.loads(path.read_text()) == {"device_screen": {"open": True}}
    assert load_ui_state(path)["device_screen"]["open"] is True


def _query_pty(monkeypatch, reply: bytes) -> tuple[str, list[object]]:
    """Run query_terminal against a pty whose 'terminal' sends ``reply``.

    Nobody reads the master side (a terminal that is not reading): the
    restore must not wait for output to drain. Returns the replies and the
    termios calls made: ``("set", when)`` / ``("flush", queue)``.
    """
    import os
    import termios

    if os.name == "nt":
        pytest.skip("no pty on Windows")
    master, slave = os.openpty()
    path = os.ttyname(slave)
    calls: list[object] = []
    real_set, real_flush = termios.tcsetattr, termios.tcflush

    def record_set(fd, when, attrs):
        calls.append(("set", when))
        return real_set(fd, when, attrs)

    def record_flush(fd, queue):
        calls.append(("flush", queue))
        return real_flush(fd, queue)

    monkeypatch.setattr(termios, "tcsetattr", record_set)
    monkeypatch.setattr(termios, "tcflush", record_flush)
    os.write(master, reply)
    try:
        out = terminal_graphics.query_terminal(
            "\x1b[c", timeout=0.05, grace=0.05, tty_path=path
        )
    finally:
        os.close(master)
        os.close(slave)
    return out, calls


def test_query_keeps_typed_keys_when_the_terminal_answers(monkeypatch) -> None:
    import termios

    out, calls = _query_pty(monkeypatch, b"\x1b[?62;4;22c")
    assert out.endswith("\x1b[?62;4;22c")
    # restored without dropping input
    assert calls[-1] == ("set", termios.TCSANOW)
    assert not [c for c in calls if c[0] == "flush"]


def test_query_flushes_late_replies_instead_of_leaking_keys(monkeypatch) -> None:
    """No DA1 sentinel by the deadline: whatever is still coming (the rest
    of the replies) must not reach Textual as keystrokes.
    """
    import termios

    _out, calls = _query_pty(monkeypatch, b"\x1bP>|iTerm2 3.5")  # no DA1
    assert ("set", termios.TCSAFLUSH) not in calls  # would wait for a drain
    assert calls[-1] == ("flush", termios.TCIFLUSH)


def test_terminal_is_not_queried_over_ssh_or_without_the_extra(monkeypatch) -> None:
    import importlib.util

    from sandroid.tui import launcher

    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    assert launcher._may_query() is True
    monkeypatch.setenv("SSH_CONNECTION", "10.0.0.1 5000 10.0.0.2 22")
    assert launcher._may_query() is False
    monkeypatch.delenv("SSH_CONNECTION")
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert launcher._may_query() is False
