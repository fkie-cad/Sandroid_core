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

from sandroid.services.device_settings_service import SettingsResult
from sandroid.tui.modals.device_settings_modal import DeviceSettingsModal

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
    return svc


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

        assert "[$success]Location applied[/]" in status
        assert "[$error]Timezone failed: no root shell[/]" in status
        assert "[$error]Accelerometer failed: invalid value[/]" in status
        assert "[$success]WiFi applied[/]" in status
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
