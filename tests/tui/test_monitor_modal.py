"""Headless Textual Pilot tests for MonitorConfigModal (opened with ``o``).

Covers the multi-path row list added for the kprobe backend:

- ``_get_default_path`` falls back to the configured
  ``device_paths.default_monitor_path`` (Decision D) when no spotlight app is
  selected, and to ``"/data/"`` when config is unavailable.
- ``_compute_effective_kprobe`` is ``True`` only when the backend is
  ``"kprobe"`` AND the cached availability verdict is exactly ``True`` (a
  ``None`` verdict counts as NOT kprobe -> safe single-path).
- Adding then removing a path row (kprobe backend), and never removing the
  last remaining row.
- The "+ Add path" button is absent (multi-path hint shown, remove buttons
  hidden) when the effective backend is fsmon or availability is unknown.
- ``_start`` collects every non-empty row into ``target_paths`` with
  ``target_path == target_paths[0]``; ``_validate`` requires absolute,
  non-empty paths.

``get_spotlight_service`` is stubbed everywhere so the modal renders in its
path-only mode (no PID -> no RadioSet), keeping the tests deterministic
regardless of any device attached to the developer's machine.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.app import App
from textual.widgets import Button, Input, Static

from sandroid.tui.controllers.monitor_controller import MonitorConfig
from sandroid.tui.modals import monitor_modal
from sandroid.tui.modals.monitor_modal import MonitorConfigModal


class _StubSpotlight:
    """Spotlight service with no selected app (path-only modal mode)."""

    def get_app_tuple(self):
        return None

    def get_pid(self):
        return None

    def is_spawn_mode(self):
        return False

    def get_spawn_package(self):
        return None


def _make_config(backend: str = "fsmon", default_path: str = "/data/"):
    """Build a minimal config namespace matching the fields the modal reads."""
    return SimpleNamespace(
        tui=SimpleNamespace(monitor_backend=backend),
        device_paths=SimpleNamespace(default_monitor_path=default_path),
    )


@pytest.fixture(autouse=True)
def _stub_spotlight(monkeypatch):
    """Force the modal into path-only mode with no spotlight app."""
    monkeypatch.setattr(monitor_modal, "get_spotlight_service", _StubSpotlight)


def _patch_backend(monkeypatch, backend: str, availability, default_path="/data/"):
    """Point the modal's ``get_config`` + ``cached_availability`` at test values."""
    monkeypatch.setattr(
        monitor_modal,
        "get_config",
        lambda: _make_config(backend=backend, default_path=default_path),
    )
    monkeypatch.setattr(
        monitor_modal.KprobeTracer,
        "cached_availability",
        classmethod(lambda cls: availability),
    )


class _ModalHarness(App):
    """Pushes MonitorConfigModal as the app's first screen."""

    def on_mount(self) -> None:
        self.push_screen(MonitorConfigModal())


# -- _get_default_path (Decision D) --------------------------------------------


def test_get_default_path_uses_configured_default(monkeypatch) -> None:
    """No spotlight app -> prefill comes from device_paths.default_monitor_path."""
    _patch_backend(
        monkeypatch, "fsmon", availability=None, default_path="/sdcard/Download"
    )
    modal = MonitorConfigModal()
    assert modal._get_default_path() == "/sdcard/Download"


def test_get_default_path_falls_back_when_config_errors(monkeypatch) -> None:
    """A broken get_config() falls back to the hardcoded '/data/'."""

    def _boom():
        raise RuntimeError("no config")

    monkeypatch.setattr(monitor_modal, "get_config", _boom)
    monkeypatch.setattr(
        monitor_modal.KprobeTracer,
        "cached_availability",
        classmethod(lambda cls: None),
    )
    modal = MonitorConfigModal()
    assert modal._get_default_path() == "/data/"


# -- _compute_effective_kprobe -------------------------------------------------


@pytest.mark.parametrize(
    ("backend", "availability", "expected"),
    [
        ("kprobe", True, True),
        ("kprobe", None, False),
        ("kprobe", False, False),
        ("fsmon", True, False),
        ("fsmon", None, False),
    ],
)
def test_effective_kprobe_gating(monkeypatch, backend, availability, expected) -> None:
    _patch_backend(monkeypatch, backend, availability=availability)
    assert MonitorConfigModal._compute_effective_kprobe() is expected


def test_effective_kprobe_false_on_config_error(monkeypatch) -> None:
    def _boom():
        raise RuntimeError("no config")

    monkeypatch.setattr(monitor_modal, "get_config", _boom)
    assert MonitorConfigModal._compute_effective_kprobe() is False


# -- Row list (kprobe backend) -------------------------------------------------


@pytest.mark.asyncio
async def test_add_and_remove_path_row(monkeypatch) -> None:
    """kprobe: '+ Add path' mounts a row; remove drops it; last row is kept."""
    _patch_backend(monkeypatch, "kprobe", availability=True)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, MonitorConfigModal)
        assert modal._effective_kprobe is True

        assert len(modal.query(".path-row")) == 1

        # Add a row.
        modal.query_one("#path-add", Button).press()
        await pilot.pause()
        assert len(modal.query(".path-row")) == 2

        # Remove the first row -> back to one.
        first_remove = list(modal.query(".path-remove"))[0]
        first_remove.press()
        await pilot.pause()
        assert len(modal.query(".path-row")) == 1

        # Removing the last remaining row is a no-op.
        list(modal.query(".path-remove"))[0].press()
        await pilot.pause()
        assert len(modal.query(".path-row")) == 1


@pytest.mark.asyncio
async def test_add_path_hidden_for_fsmon(monkeypatch) -> None:
    """Fsmon backend: no add button, multi-path hint shown, remove hidden."""
    _patch_backend(monkeypatch, "fsmon", availability=True)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert modal._effective_kprobe is False

        assert len(modal.query("#path-add")) == 0
        assert len(modal.query("#multipath-hint")) == 1
        assert isinstance(modal.query_one("#multipath-hint"), Static)

        # Single row, and its remove button is hidden.
        assert len(modal.query(".path-row")) == 1
        remove_btn = modal.query_one(".path-remove", Button)
        assert remove_btn.has_class("hidden")


@pytest.mark.asyncio
async def test_add_path_hidden_when_availability_unknown(monkeypatch) -> None:
    """Kprobe backend but None (never probed) verdict stays single-path."""
    _patch_backend(monkeypatch, "kprobe", availability=None)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen
        assert modal._effective_kprobe is False
        assert len(modal.query("#path-add")) == 0
        assert len(modal.query("#multipath-hint")) == 1


# -- _start / _validate --------------------------------------------------------


@pytest.mark.asyncio
async def test_start_builds_target_paths_from_all_rows(monkeypatch) -> None:
    """_start collects every non-empty row; target_path == target_paths[0]."""
    _patch_backend(monkeypatch, "kprobe", availability=True)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen

        modal.query_one("#path-add", Button).press()
        await pilot.pause()

        inputs = list(modal.query(".path-input"))
        assert len(inputs) == 2
        inputs[0].value = "/data/data/com.example.app"
        inputs[1].value = "/sdcard/Download"

        captured: dict[str, MonitorConfig] = {}
        modal._dismiss_with_refresh = lambda result: captured.update(result=result)

        modal._start()

        config = captured["result"]
        assert isinstance(config, MonitorConfig)
        assert config.cancelled is False
        assert config.target_paths == [
            "/data/data/com.example.app",
            "/sdcard/Download",
        ]
        assert config.target_path == config.target_paths[0]


@pytest.mark.asyncio
async def test_start_ignores_empty_rows(monkeypatch) -> None:
    """Blank rows are dropped; a single valid path still starts."""
    _patch_backend(monkeypatch, "kprobe", availability=True)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen

        modal.query_one("#path-add", Button).press()
        await pilot.pause()

        inputs = list(modal.query(".path-input"))
        inputs[0].value = "/sdcard/"
        inputs[1].value = "   "  # whitespace-only -> dropped

        captured: dict[str, MonitorConfig] = {}
        modal._dismiss_with_refresh = lambda result: captured.update(result=result)

        modal._start()

        config = captured["result"]
        assert config.target_paths == ["/sdcard/"]
        assert config.target_path == "/sdcard/"


@pytest.mark.asyncio
async def test_validate_rejects_relative_and_empty(monkeypatch) -> None:
    """_validate demands at least one non-empty, absolute path."""
    _patch_backend(monkeypatch, "kprobe", availability=True)
    app = _ModalHarness()
    async with app.run_test() as pilot:
        await pilot.pause()
        modal = app.screen

        only_input = modal.query_one(".path-input", Input)

        only_input.value = ""
        valid, msg = modal._validate()
        assert valid is False
        assert "path to monitor" in msg

        only_input.value = "relative/path"
        valid, msg = modal._validate()
        assert valid is False
        assert "absolute" in msg

        only_input.value = "/data/"
        valid, _ = modal._validate()
        assert valid is True
