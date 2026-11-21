"""Pilot tests for DeviceSettingsModal (Shift+E): Apply runs in a worker.

Every Apply does adb/emulator-console round trips, so the modal must run them
off the UI thread, lock its Apply buttons meanwhile, colour results by
outcome (success vs error theme tokens, plain words, no glyphs) and survive
being closed while a run is still going.
"""

from __future__ import annotations

import threading

import pytest
from pilot_helpers import settle, until
from textual.app import App
from textual.widgets import Button, Input, Static

from sandroid.core.adb import Adb
from sandroid.services.device_settings_service import SettingsResult
from sandroid.tui.modals.device_settings_modal import DeviceSettingsModal

SERIAL = "emulator-5560"

APPLY_BUTTONS = (
    "#btn-apply-location",
    "#btn-apply-environment",
    "#btn-apply-sensors",
    "#btn-apply-network",
)


class _FakeService:
    """Stands in for DeviceSettingsService; GPS can be held at a gate."""

    def __init__(self, gated: bool = False) -> None:
        self.gate = threading.Event()
        if not gated:
            self.gate.set()
        self.started = threading.Event()
        self.finished = threading.Event()
        self.gps_threads: list[int] = []

    def is_geopy_available(self) -> bool:
        return False

    def set_gps_location(self, lat: float, lon: float) -> SettingsResult:
        self.gps_threads.append(threading.get_ident())
        self.started.set()
        try:
            # Bounded: a regression that runs this on the UI thread fails
            # the test instead of hanging the run forever.
            assert self.gate.wait(10), "gate never opened"
            return SettingsResult(success=True, message=f"GPS set to {lat}, {lon}")
        finally:
            self.finished.set()

    def set_timezone(self, tz: str) -> SettingsResult:
        return SettingsResult(
            success=False, message="Failed to set timezone", error="no root shell"
        )

    def set_sensor(self, sensor_type: str, level: int) -> SettingsResult:
        raise AssertionError("invalid input must not reach the service")

    def _ok(self, _enabled: bool) -> SettingsResult:
        return SettingsResult(success=True, message="toggled")

    toggle_wifi = toggle_mobile_data = toggle_bluetooth = _ok


class _Harness(App):
    def on_mount(self) -> None:
        self.push_screen(DeviceSettingsModal(is_emulator=True, has_root=True))


@pytest.fixture
def service(monkeypatch, request) -> _FakeService:
    svc = _FakeService(gated=getattr(request, "param", False))
    monkeypatch.setattr("sandroid.services.get_device_settings_service", lambda: svc)
    # A device is selected unless a test says otherwise.
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: SERIAL))
    return svc


@pytest.fixture(autouse=True)
def _own_ui_state(monkeypatch, tmp_path) -> None:
    """Each test gets its own ``tui_state.json`` (the modal remembers its tab)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))


def _status(modal: DeviceSettingsModal) -> str:
    return str(modal.query_one("#status-label", Static).content)


def _apply_disabled(modal: DeviceSettingsModal) -> list[bool]:
    return [modal.query_one(b, Button).disabled for b in APPLY_BUTTONS]


async def _open(pilot) -> DeviceSettingsModal:
    await until(pilot, lambda: isinstance(pilot.app.screen, DeviceSettingsModal))
    await settle(pilot)
    modal = pilot.app.screen
    modal.query_one("#input-latitude", Input).value = "52.52"
    modal.query_one("#input-longitude", Input).value = "13.405"
    return modal


@pytest.mark.asyncio
@pytest.mark.parametrize("service", [True], indirect=True)
async def test_apply_runs_off_the_ui_thread_with_buttons_locked(service) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        modal = await _open(pilot)
        assert _apply_disabled(modal) == [False, False, False, False]

        modal.query_one("#btn-apply-location", Button).press()
        await until(pilot, service.started.is_set, msg="apply never started")
        await settle(pilot)

        # The service call is still blocked at the gate, yet the UI loop ran:
        # the handler returned before the adb work finished.
        assert not service.finished.is_set()
        assert service.gps_threads[0] != threading.get_ident()
        assert _status(modal) == "Applying..."
        assert _apply_disabled(modal) == [True, True, True, True]

        # A second Apply while busy is ignored, not queued.
        modal.action_apply_all()
        await settle(pilot)
        assert len(service.gps_threads) == 1

        service.gate.set()
        await until(pilot, lambda: "applied" in _status(modal))
        assert _apply_disabled(modal) == [False, False, False, False]
        assert modal._messages == ["GPS set to 52.52, 13.405"]


@pytest.mark.asyncio
async def test_failures_use_error_style_and_successes_success_style(
    service,
) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        modal = await _open(pilot)
        modal.query_one("#input-timezone", Input).value = "Europe/Berlin"
        modal.query_one("#input-accelerometer", Input).value = "abc"

        await pilot.press("ctrl+s")
        await until(pilot, lambda: "Bluetooth" in _status(modal))
        status = _status(modal)

        assert "[$success]Location applied: GPS set to 52.52, 13.405[/]" in status
        assert "[$error]Timezone failed: no root shell[/]" in status
        assert "[$error]Accelerometer failed: invalid value[/]" in status
        assert "[$success]WiFi applied: toggled[/]" in status
        assert "green" not in status
        for glyph in ("✓", "✗", "✔", "✘", "•", " · "):
            assert glyph not in status
        # The markup resolves against the theme and renders as plain words.
        plain = modal.query_one("#status-label", Static).visual.plain
        assert "Timezone failed: no root shell" in plain
        assert "$" not in plain
        # Only successes count as applied.
        assert "Failed to set timezone" not in modal._messages


@pytest.mark.asyncio
async def test_empty_tab_warns_without_starting_a_run(service) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        await until(pilot, lambda: isinstance(app.screen, DeviceSettingsModal))
        await settle(pilot)
        modal = app.screen
        modal.query_one("#btn-apply-location", Button).press()
        await settle(pilot)
        assert _status(modal) == "[$warning]Enter latitude and longitude[/]"
        assert not service.started.is_set()
        assert not modal._applying


@pytest.mark.asyncio
async def test_no_device_selected_refuses_to_start(service, monkeypatch) -> None:
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: None))
    monkeypatch.setattr(Adb, "selected_serial", classmethod(lambda cls: None))
    app = _Harness()
    async with app.run_test() as pilot:
        modal = await _open(pilot)
        modal.query_one("#btn-apply-location", Button).press()
        await settle(pilot)
        assert _status(modal) == "[$error]No device selected[/]"
        assert not service.started.is_set()
        assert not modal._applying
        assert _apply_disabled(modal) == [False, False, False, False]


@pytest.mark.asyncio
async def test_run_is_pinned_to_the_selected_serial(service, monkeypatch) -> None:
    monkeypatch.setattr(Adb, "get_target_device", classmethod(lambda cls: None))
    monkeypatch.setattr(Adb, "selected_serial", classmethod(lambda cls: "emu-9"))
    seen: list[str | None] = []
    real_gps = service.set_gps_location

    def gps(lat: float, lon: float) -> SettingsResult:
        from sandroid.core import adb as adb_mod

        seen.append(getattr(adb_mod._thread_target, "serial", None))
        return real_gps(lat, lon)

    service.set_gps_location = gps
    app = _Harness()
    async with app.run_test() as pilot:
        modal = await _open(pilot)
        modal.query_one("#btn-apply-location", Button).press()
        await until(pilot, lambda: "applied" in _status(modal))
        assert seen == ["emu-9"]


@pytest.mark.asyncio
@pytest.mark.parametrize("service", [True], indirect=True)
async def test_escape_closes_the_modal_during_a_run(service) -> None:
    app = _Harness()
    async with app.run_test() as pilot:
        modal = await _open(pilot)
        modal.query_one("#btn-apply-location", Button).press()
        await until(pilot, service.started.is_set, msg="apply never started")

        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, DeviceSettingsModal))

        # The worker finishes after the modal is gone; its result must be
        # dropped quietly.
        service.gate.set()
        await until(pilot, service.finished.is_set)
        await until(pilot, lambda: not modal._applying)
        await settle(pilot)
        assert app.is_running
        assert app._exception is None


# -- Actions tab (device-actions registry) ----------------------------------------


class _ActionsHarness(App):
    def __init__(self, is_emulator: bool = True) -> None:
        super().__init__()
        self._is_emulator = is_emulator

    def on_mount(self) -> None:
        self.push_screen(
            DeviceSettingsModal(is_emulator=self._is_emulator, has_root=True)
        )


class _FakeRegistry:
    """Stands in for ``run_action`` / the background jobs; can gate a run."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self.gate.set()
        self.started = threading.Event()
        self.runs: list[tuple] = []
        self.threads: list[int] = []
        self.jobs: list = []
        self.stopped: list[str] = []
        self.result = None

    def run_action(self, action_id, serial, params=None, *, actor="user"):
        from sandroid.services.device_actions import ActionResult

        self.runs.append((action_id, serial, dict(params or {}), actor))
        self.threads.append(threading.get_ident())
        self.started.set()
        assert self.gate.wait(10), "gate never opened"
        return self.result or ActionResult(action_id, True, "SMS received from DHL")

    def running_jobs(self, serial=None):
        return list(self.jobs)

    def stop_job(self, job_id, wait=5.0):
        self.stopped.append(job_id)
        self.jobs = [j for j in self.jobs if j.id != job_id]
        return True


@pytest.fixture
def registry(monkeypatch, service) -> _FakeRegistry:
    fake = _FakeRegistry()
    from sandroid.services import device_actions

    monkeypatch.setattr(device_actions, "run_action", fake.run_action)
    monkeypatch.setattr(device_actions, "running_jobs", fake.running_jobs)
    monkeypatch.setattr(device_actions, "stop_job", fake.stop_job)
    return fake


async def _open_actions(pilot) -> DeviceSettingsModal:
    from textual.widgets import TabbedContent

    await until(pilot, lambda: isinstance(pilot.app.screen, DeviceSettingsModal))
    modal = pilot.app.screen
    modal.query_one("#settings-tabs", TabbedContent).active = "tab-actions"
    await until(pilot, lambda: modal._built_for is not None)
    await settle(pilot)
    return modal


async def _pick(pilot, modal: DeviceSettingsModal, action_id: str) -> None:
    from textual.widgets import Select

    modal.query_one("#action-select", Select).value = action_id
    await until(pilot, lambda: modal._built_for == action_id)
    await settle(pilot)


@pytest.mark.asyncio
async def test_actions_tab_shows_the_fields_of_the_picked_action(registry) -> None:
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        assert modal._built_for == "sms.receive"
        assert modal.query_one("#action-param-sender", Input).placeholder == (
            "e.g. DHL or +4915112345678"
        )
        modal.query_one("#action-param-text", Input)

        await _pick(pilot, modal, "gps.route")
        from textual.widgets import Select

        assert modal.query_one("#action-param-route", Select).value == "berlin-walk"
        assert modal.query_one("#action-param-interval_s", Input).value == "2"
        assert not modal.query("#action-param-sender")

        await _pick(pilot, modal, "net.wifi")
        from textual.widgets import Switch

        assert modal.query_one("#action-param-on", Switch).value is True

        await _pick(pilot, modal, "call.hangup")  # no parameters at all
        assert not modal.query("#action-params Horizontal")
        assert not modal.query_one("#btn-run-action", Button).disabled


@pytest.mark.asyncio
async def test_run_goes_off_the_ui_thread_and_shows_the_result(registry) -> None:
    registry.gate.clear()
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        modal.query_one("#action-param-sender", Input).value = "DHL"
        modal.query_one("#action-param-text", Input).value = "Paket kommt"

        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, registry.started.is_set, msg="run never started")
        await settle(pilot)
        assert registry.threads[0] != threading.get_ident()
        assert modal.query_one("#btn-run-action", Button).disabled
        assert _status(modal) == "Running: Receive an SMS..."

        registry.gate.set()
        await until(pilot, lambda: "SMS received" in _status(modal))
        assert _status(modal) == "[$success]SMS received from DHL[/]"
        assert not modal.query_one("#btn-run-action", Button).disabled
        assert registry.runs == [
            ("sms.receive", SERIAL, {"sender": "DHL", "text": "Paket kommt"}, "user")
        ]
        assert modal._messages == ["SMS received from DHL"]


@pytest.mark.asyncio
async def test_ctrl_s_on_the_actions_tab_runs_the_action(registry, service) -> None:
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        await _pick(pilot, modal, "power.battery")
        modal.query_one("#action-param-level", Input).value = "15"
        await pilot.press("ctrl+s")
        await until(pilot, lambda: registry.runs)
        assert registry.runs[0][:3] == ("power.battery", SERIAL, {"level": "15"})
        assert not service.gps_threads  # not "apply all settings"


@pytest.mark.asyncio
async def test_refusals_and_failures_are_red_words(registry) -> None:
    from sandroid.services.device_actions import ActionResult

    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        registry.result = ActionResult(
            "sms.receive", False, "Sender: at most 11 letters", refused=True
        )
        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, lambda: "not run" in _status(modal))
        assert _status(modal) == (
            "[$error]Receive an SMS not run: Sender: at most 11 letters[/]"
        )
        registry.result = ActionResult("sms.receive", False, "device offline")
        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, lambda: "failed" in _status(modal))
        assert _status(modal) == "[$error]Receive an SMS failed: device offline[/]"
        for glyph in ("✓", "✗", "▸", "•"):
            assert glyph not in _status(modal)
        assert modal._messages == []


@pytest.mark.asyncio
async def test_an_action_result_stays_on_its_tab(registry) -> None:
    """N5 V9: the last result does not linger on every tab, nor under the
    next action; a result that arrives on another tab waits for its tab.
    """
    from textual.widgets import TabbedContent

    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        tabs = modal.query_one("#settings-tabs", TabbedContent)
        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, lambda: "SMS received" in _status(modal))

        tabs.active = "tab-location"
        await until(pilot, lambda: _status(modal) == "")
        tabs.active = "tab-actions"
        await until(pilot, lambda: "SMS received" in _status(modal))

        await _pick(pilot, modal, "call.incoming")
        assert _status(modal) == ""

        # A run that finishes while another tab is shown.
        registry.gate.clear()
        registry.started.clear()
        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, registry.started.is_set)
        await settle(pilot)
        tabs.active = "tab-network"
        await settle(pilot)
        registry.gate.set()
        await until(pilot, lambda: not modal._action_busy)
        await settle(pilot)
        assert _status(modal) == ""
        tabs.active = "tab-actions"
        await until(pilot, lambda: "SMS received" in _status(modal))


@pytest.mark.asyncio
async def test_emulator_only_actions_are_locked_on_a_physical_device(
    registry,
) -> None:
    app = _ActionsHarness(is_emulator=False)
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        assert modal.query_one("#btn-run-action", Button).disabled
        assert modal.query_one("#action-param-sender", Input).disabled
        help_text = str(modal.query_one("#action-help", Static).content)
        assert "Works on an emulator only." in help_text
        await pilot.press("ctrl+s")
        await settle(pilot)
        assert registry.runs == []
        assert "works on an emulator only" in _status(modal)

        await _pick(pilot, modal, "net.airplane")  # fine on a phone
        assert not modal.query_one("#btn-run-action", Button).disabled


@pytest.mark.asyncio
async def test_background_actions_are_listed_and_can_be_stopped(registry) -> None:
    from types import SimpleNamespace

    registry.jobs = [
        SimpleNamespace(id="job-7", title="GPS route Berlin walk",
                        progress="fix 3 of 40", serial=SERIAL)
    ]  # fmt: skip
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        await until(pilot, lambda: modal.query("#btn-stop-job-7"))
        label = modal.query_one("#job-label-job-7", Static)
        assert str(label.content) == (
            "GPS route Berlin walk [$success]●[/] running, fix 3 of 40"
        )
        assert str(modal.query_one("#action-jobs-title", Static).content) == (
            "Running in the background"
        )
        registry.jobs[0].progress = "fix 4 of 40"
        await modal._refresh_jobs()
        assert str(label.content).endswith("running, fix 4 of 40")

        modal.query_one("#btn-stop-job-7", Button).press()
        await until(pilot, lambda: registry.stopped == ["job-7"])
        await until(pilot, lambda: "stopped" in _status(modal))
        assert _status(modal) == "[$success]Background action stopped[/]"
        await until(pilot, lambda: not modal.query("#btn-stop-job-7"))
        assert str(modal.query_one("#action-jobs-title", Static).content) == ""


@pytest.mark.asyncio
async def test_closing_during_an_action_run_is_quiet(registry) -> None:
    registry.gate.clear()
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        modal.query_one("#btn-run-action", Button).press()
        await until(pilot, registry.started.is_set)
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, DeviceSettingsModal))
        registry.gate.set()
        await until(pilot, lambda: not modal._action_busy)
        await settle(pilot)
        assert app.is_running
        assert app._exception is None


@pytest.mark.asyncio
async def test_shift_arrows_cycle_the_tabs_and_tab_reaches_the_picker(
    registry,
) -> None:
    from textual.widgets import Select, TabbedContent, Tabs

    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        await until(pilot, lambda: isinstance(app.screen, DeviceSettingsModal))
        await settle(pilot)
        modal = app.screen
        tabs = modal.query_one("#settings-tabs", TabbedContent)
        modal.query_one("#settings-tabs Tabs", Tabs).focus()
        await settle(pilot)
        await pilot.press("shift+left")  # wraps: Location -> Actions
        await settle(pilot)
        assert tabs.active == "tab-actions"
        assert isinstance(app.focused, Tabs)
        await pilot.press("tab")
        await settle(pilot)
        assert app.focused is modal.query_one("#action-select", Select)
        await pilot.press("shift+right")
        await settle(pilot)
        assert tabs.active == "tab-location"


# -- Keyboard navigation (Shift+E E2E findings) -------------------------------


async def _wait_modal(pilot) -> DeviceSettingsModal:
    await until(pilot, lambda: isinstance(pilot.app.screen, DeviceSettingsModal))
    await settle(pilot)
    return pilot.app.screen


@pytest.mark.asyncio
async def test_shift_arrows_switch_tabs_right_after_opening(registry) -> None:
    """The modal opens on the tab bar (not in a text field that would eat
    Shift+Left/Right), without scrolling the title away.
    """
    from textual.widgets import TabbedContent, Tabs

    app = _ActionsHarness()
    async with app.run_test(size=(100, 30)) as pilot:
        modal = await _wait_modal(pilot)
        tabs = modal.query_one("#settings-tabs", TabbedContent)
        assert isinstance(app.focused, Tabs)
        assert modal.query_one(".modal-container").scroll_y == 0
        await pilot.press("shift+right")
        await settle(pilot)
        assert tabs.active == "tab-environment"
        await pilot.press("shift+left", "shift+left")
        await settle(pilot)
        assert tabs.active == "tab-actions"


@pytest.mark.asyncio
async def test_escape_closes_an_open_dropdown_before_the_modal(registry) -> None:
    from textual.widgets import Select

    app = _ActionsHarness()
    async with app.run_test(size=(120, 35)) as pilot:
        modal = await _open_actions(pilot)
        picker = modal.query_one("#action-select", Select)
        picker.focus()
        await settle(pilot)
        await pilot.press("enter")
        await until(pilot, lambda: picker.expanded)

        await pilot.press("escape")
        await settle(pilot)
        assert app.screen is modal
        assert not picker.expanded
        assert app.focused is picker
        assert modal._built_for == "sms.receive"  # the choice is unchanged

        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, DeviceSettingsModal))


@pytest.mark.asyncio
async def test_the_last_tab_is_remembered_in_the_ui_state(registry, tmp_path) -> None:
    import json

    from textual.widgets import TabbedContent

    app = _ActionsHarness()
    async with app.run_test(size=(120, 35)) as pilot:
        modal = await _wait_modal(pilot)
        assert modal.query_one("#settings-tabs", TabbedContent).active == (
            "tab-location"
        )
        await pilot.press("shift+left")  # wraps to Actions
        await settle(pilot)
        await pilot.press("escape")
        await until(pilot, lambda: not isinstance(app.screen, DeviceSettingsModal))
        state = json.loads((tmp_path / "sandroid" / "tui_state.json").read_text())
        assert state["device_settings_tab"] == "tab-actions"

        app.push_screen(DeviceSettingsModal())
        modal = await _wait_modal(pilot)
        assert modal.query_one("#settings-tabs", TabbedContent).active == (
            "tab-actions"
        )
        await until(pilot, lambda: modal._built_for is not None)


@pytest.mark.asyncio
async def test_an_unknown_remembered_tab_falls_back_to_location(
    registry,
) -> None:
    from textual.widgets import TabbedContent

    from sandroid.config.ui_state import update_ui_state

    update_ui_state("device_settings_tab", "tab-gone")
    app = _ActionsHarness()
    async with app.run_test(size=(120, 35)) as pilot:
        modal = await _wait_modal(pilot)
        assert modal.query_one("#settings-tabs", TabbedContent).active == (
            "tab-location"
        )


def _in_view(container, widget) -> bool:
    return container.content_region.contains_region(widget.region)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(120, 35), (100, 30)])
async def test_actions_tab_scrolls_with_the_keyboard(registry, size) -> None:
    """Content taller than the modal scrolls: a scrollbar shows, the focused
    widget scrolls into view, PageUp/PageDown/Up/Down scroll.
    """
    app = _ActionsHarness()
    async with app.run_test(size=size) as pilot:
        modal = await _open_actions(pilot)
        container = modal.query_one(".modal-container")
        assert container.max_scroll_y > 0
        assert container.show_vertical_scrollbar

        close = modal.query_one("#btn-close", Button)
        for _ in range(12):  # Tab through the tab's widgets to Close
            if app.focused is close:
                break
            await pilot.press("tab")
            await settle(pilot)
            assert _in_view(container, app.focused), app.focused
        assert app.focused is close
        await until(pilot, lambda: _in_view(container, close))

        await pilot.press("pageup")
        await until(pilot, lambda: container.scroll_y == 0)
        await pilot.press("down")
        await until(pilot, lambda: container.scroll_y == 1)
        await pilot.press("pagedown")
        await until(pilot, lambda: container.scroll_y == container.max_scroll_y)


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [(120, 35), (100, 30)])
async def test_action_dropdown_reaches_the_network_actions_by_keyboard(
    registry, size
) -> None:
    from textual.color import Color
    from textual.widgets import Select
    from textual.widgets._select import SelectOverlay

    app = _ActionsHarness()
    async with app.run_test(size=size) as pilot:
        modal = await _open_actions(pilot)
        picker = modal.query_one("#action-select", Select)
        picker.focus()
        await settle(pilot)
        await pilot.press("enter")
        await until(pilot, lambda: picker.expanded)
        overlay = picker.query_one(SelectOverlay)
        assert overlay.max_scroll_y > 0
        assert overlay.show_vertical_scrollbar
        # Drawn in the accent colour, not the theme's near-invisible default.
        primary = Color.parse(app.get_css_variables()["primary"])
        assert overlay.styles.scrollbar_color.rgb == primary.rgb

        await pilot.press("end")
        await settle(pilot)
        assert overlay.scroll_y == overlay.max_scroll_y
        await pilot.press("enter")
        await until(pilot, lambda: modal._built_for.startswith("net."))


@pytest.mark.asyncio
async def test_action_inputs_show_their_whole_box_and_an_empty_value(registry) -> None:
    """N4-V10: the Sender/Text inputs showed only their top border, and the
    example looked like a value (Run then said "Sender: enter a value").
    """
    app = _ActionsHarness()
    async with app.run_test(size=(120, 50)) as pilot:
        modal = await _open_actions(pilot)
        for name in ("sender", "text"):
            field = modal.query_one(f"#action-param-{name}", Input)
            row = field.parent
            assert field.value == ""
            assert field.placeholder.startswith("e.g. ")
            assert field.region.height == 3
            assert field.region.y >= row.region.y
            assert field.region.bottom <= row.region.bottom


def _mouse(cls, app, widget):
    """A terminal mouse event at the centre of *widget* (as the driver posts)."""
    x, y = widget.region.center
    return cls(
        widget=None, x=x, y=y, delta_x=0, delta_y=0, button=1,
        shift=False, meta=False, ctrl=False, screen_x=x, screen_y=y,
    )  # fmt: skip


@pytest.mark.asyncio
async def test_fast_typing_into_sender_stays_there_when_a_click_follows(
    registry,
) -> None:
    """N4-B12: "DHL" typed fast into Sender, then a click on Text. The
    click must not overtake the typed-ahead keys (they ended up as "D" in
    Sender and "HL..." in Text).
    """
    from pilot_helpers import boot
    from textual import events
    from textual.widgets import TabbedContent

    from sandroid.tui.app import SandroidTUI

    app = SandroidTUI()
    async with app.run_test(size=(200, 50)) as pilot:
        await boot(app, pilot)
        app.push_screen(DeviceSettingsModal(is_emulator=True, has_root=True))
        await until(pilot, lambda: isinstance(app.screen, DeviceSettingsModal))
        modal = app.screen
        await until(pilot, lambda: modal.query("#settings-tabs"))
        await settle(pilot)
        modal.query_one("#settings-tabs", TabbedContent).active = "tab-actions"
        await until(pilot, lambda: modal._built_for == "sms.receive")
        await settle(pilot)
        sender = modal.query_one("#action-param-sender", Input)
        text = modal.query_one("#action-param-text", Input)
        sender.focus()
        await settle(pilot)

        app.KEY_SETTLE_SECONDS = 60.0  # never released early by a slow host
        # One burst, as the terminal delivers it: keys, a click, more keys.
        for key in "DHL":
            app.post_message(events.Key(key, key))
        app.post_message(_mouse(events.MouseDown, app, text))
        app.post_message(_mouse(events.MouseUp, app, text))
        for key in "Par":
            app.post_message(events.Key(key, key))
        await until(pilot, lambda: len(sender.value + text.value) == 6)
        await settle(pilot)
        assert (sender.value, text.value) == ("DHL", "Par")
        assert app.focused is text
