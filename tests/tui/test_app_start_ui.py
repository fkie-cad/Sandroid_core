"""Where the app-selection rule asks the user (App lens, Objection).

⇧P on a running app and a start-time bypass toggled on a running app ask
before any restart; No keeps the app. Objection defaults to attach for a
running app and warns while spawn (which restarts it) is selected. Waits are
by condition (no fixed sleeps).
"""

from __future__ import annotations

import time

from textual.app import App

from sandroid import services
from sandroid.services import app_start
from sandroid.services.spotlight_service import SpotlightService
from sandroid.tui.modals.confirm_modal import ConfirmModal
from sandroid.tui.widgets import app_lens
from sandroid.tui.widgets.spotlight_panel import SpotlightPanel

PKG = "org.wikipedia"


async def _until(pilot, cond, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < deadline, "condition not met"
        await pilot.pause(0.01)


class _Harness(App):
    def compose(self):
        yield SpotlightPanel(id="spotlight")


def _panel_env(monkeypatch, *, pid=77):
    svc = SpotlightService(job_manager_factory=lambda: None)
    svc.set_app(PKG, pid=pid)
    monkeypatch.setattr(services, "get_spotlight_service", lambda: svc)
    monkeypatch.setattr(app_lens.AppLensSections, "track", lambda *a, **k: None)
    monkeypatch.setattr(SpotlightPanel, "_poll_running_state", lambda self: None)
    ran: list[str] = []
    monkeypatch.setattr(
        SpotlightPanel,
        "_run_frida_action",
        lambda self, work, label, feature: ran.append(label),
    )
    return svc, ran


async def test_shift_p_on_a_running_app_asks_and_no_keeps_it(monkeypatch):
    _svc, ran = _panel_env(monkeypatch)
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda pkg, frida_fallback=False: (app_start.Liveness.RUNNING, 77),
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(SpotlightPanel)
        panel.action_start_paused()
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        modal = app.screen
        assert modal.title_text == f"Restart {PKG} paused?"
        assert "(pid 77)" in modal.message_text
        assert modal.guard_typing is True
        await pilot.press("n")
        await _until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert ran == []  # kept running


async def test_shift_p_on_a_stopped_app_starts_paused_without_asking(monkeypatch):
    _svc, ran = _panel_env(monkeypatch, pid=None)
    monkeypatch.setattr(
        app_start,
        "probe_liveness",
        lambda pkg, frida_fallback=False: (app_start.Liveness.NOT_RUNNING, None),
    )
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        app.query_one(SpotlightPanel).action_start_paused()
        await _until(pilot, lambda: ran == ["start-paused"])
        assert not isinstance(app.screen, ConfirmModal)


async def test_emulator_bypass_on_a_running_app_offers_a_restart(monkeypatch):
    _svc, ran = _panel_env(monkeypatch)
    app = _Harness()
    async with app.run_test(size=(120, 30)) as pilot:
        panel = app.query_one(SpotlightPanel)
        panel._offer_restart_for("emulator")
        await _until(pilot, lambda: isinstance(app.screen, ConfirmModal))
        assert app.screen.title_text == f"Restart {PKG} now?"
        assert app.screen.yes_label == "Restart"
        assert app.screen.no_label == "Keep running"
        await pilot.press("n")
        await _until(pilot, lambda: not isinstance(app.screen, ConfirmModal))
        assert ran == []


def test_header_shows_the_run_state_and_no_mode(monkeypatch):
    svc, _ran = _panel_env(monkeypatch)
    panel = SpotlightPanel()
    assert "● running" in panel._render_header()
    assert "spawn" not in panel._render_header()
    svc.set_pid(None)
    assert "○ not running" in panel._render_header()
    assert "␣ start" in panel._render_header()
    svc.reset()
    header = panel._render_header()
    assert "use the foreground app" in header
    assert "pick an app…" in header


async def test_objection_warns_while_spawn_would_restart_the_app() -> None:
    from sandroid.tui.modals.objection_modal import ObjectionModal

    class Harness(App):
        def on_mount(self) -> None:
            self.push_screen(
                ObjectionModal(
                    package_name=PKG, initial_spawn_mode=False, running_pid=77
                )
            )

    app = Harness()
    async with app.run_test(size=(100, 30)) as pilot:
        await _until(pilot, lambda: isinstance(app.screen, ObjectionModal))
        modal = app.screen
        assert modal.config.spawn_mode is False  # running: attach by default
        assert modal._warning_text() == ""
        await pilot.press("s")
        assert modal.config.spawn_mode is True
        assert "restarts the running app (pid 77)" in modal._warning_text()
        assert "Enter confirms" in modal._warning_text()
