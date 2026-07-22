"""Headless Textual Pilot tests for SettingsScreen's FSMon event-visibility rows.

Covers the new per-category ``fsmon_event_visibility`` Settings UI: the 6
Select rows added to the General tab (``create``/``modify``/``delete``/
``rename``/``attrs``/``noise``) and the ``on_select_changed`` save-path
special-case for their ``setting-tui--fsmon_event_visibility__<category>``
ids.

The critical regression this guards against: ``SettingsController.save`` /
``_apply_setting`` does a full ``setattr`` REPLACE of the whole
``fsmon_event_visibility`` dict, not a merge. If the special-case handler
only ever inserted the one changed category into a fresh dict, saving would
silently wipe the other 5 categories back to nothing (or to their schema
defaults, whichever a naive implementation happened to default to). The
merge-safety test below seeds a *second*, non-default category before
touching a *first* one, so a regression to that bug would be caught.

The background Frida-version-fetch thread that ``SettingsScreen.on_mount``
starts is stubbed to a no-op in all tests here -- it does real network I/O
(GitHub tag listing) via a daemon thread and is unrelated to what this file
covers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Select

from sandroid.config import SandroidConfig
from sandroid.tui.screens.settings_screen import SettingsScreen

_ALL_ALWAYS_NOISE_VERBOSE = {
    "create": "always",
    "modify": "always",
    "delete": "always",
    "rename": "always",
    "attrs": "always",
    "noise": "verbose",
}


class _StubLoader:
    """Stand-in for ``ConfigLoader`` that never touches disk.

    ``SettingsController.save`` instantiates ``ConfigLoader()`` itself (no
    DI seam), so this is monkeypatched in over the class name inside the
    ``settings_controller`` module. ``load()`` hands back the exact
    pre-built config instance (not a copy) so the test can assert on it
    in-place after ``_apply_setting`` mutates it; ``detect_and_save`` never
    writes to a real file.
    """

    def __init__(self, preset_config: SandroidConfig) -> None:
        self._preset_config = preset_config

    def load(self) -> SandroidConfig:
        return self._preset_config

    def detect_and_save(self, config: SandroidConfig) -> Path:
        return Path("/dev/null")


class _SettingsHarness(App):
    """Pushes SettingsScreen with an injected config.

    Setting ``sandroid_config`` directly makes ``SettingsScreen._get_config``
    use it instead of falling back to the real on-disk ``get_config()``
    singleton, which would make tests depend on whatever the developer's
    ``~/.config/sandroid/sandroid.toml`` happens to contain.
    """

    def __init__(self, config: SandroidConfig) -> None:
        super().__init__()
        self.sandroid_config = config

    def on_mount(self) -> None:
        self.push_screen(SettingsScreen())


@pytest.fixture(autouse=True)
def _no_frida_version_fetch(monkeypatch):
    """Prevent the real background network-fetch thread from starting."""
    monkeypatch.setattr(SettingsScreen, "_fetch_frida_versions", lambda self: None)


def _visibility_select(screen: SettingsScreen, category: str) -> Select:
    return screen.query_one(f"#setting-tui--fsmon_event_visibility__{category}", Select)


@pytest.mark.asyncio
async def test_compose_renders_default_visibility_selects() -> None:
    """Schema-default config: 5 categories 'always', noise 'verbose'."""
    config = SandroidConfig()
    app = _SettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        for category, expected in _ALL_ALWAYS_NOISE_VERBOSE.items():
            select = _visibility_select(screen, category)
            assert select.value == expected, category


@pytest.mark.asyncio
async def test_compose_uses_preexisting_nondefault_visibility_values() -> None:
    """A config with non-default values populates the Selects from it."""
    config = SandroidConfig()
    config.tui.fsmon_event_visibility = {
        "create": "never",
        "modify": "verbose",
        "delete": "always",
        "rename": "never",
        "attrs": "verbose",
        "noise": "never",
    }
    app = _SettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        assert _visibility_select(screen, "create").value == "never"
        assert _visibility_select(screen, "modify").value == "verbose"
        assert _visibility_select(screen, "delete").value == "always"
        assert _visibility_select(screen, "rename").value == "never"
        assert _visibility_select(screen, "attrs").value == "verbose"
        assert _visibility_select(screen, "noise").value == "never"


@pytest.mark.asyncio
async def test_changing_one_category_preserves_others_through_save(
    monkeypatch,
) -> None:
    """Changing ONE Select must not wipe the other 5 categories on save.

    Seeds "attrs" with a non-default value ("never") *before* the edit, then
    only changes "noise". A regression to "insert one key into a fresh
    dict" would reset "attrs" to a default/blank value here -- this test
    would fail in that case.
    """
    preset_config = SandroidConfig()
    preset_config.tui.fsmon_event_visibility = {
        "create": "always",
        "modify": "always",
        "delete": "always",
        "rename": "always",
        "attrs": "never",  # pre-existing non-default value
        "noise": "verbose",
    }

    monkeypatch.setattr(
        "sandroid.tui.controllers.settings_controller.ConfigLoader",
        lambda: _StubLoader(preset_config),
    )

    app = _SettingsHarness(preset_config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        noise_select = _visibility_select(screen, "noise")
        noise_select.value = "never"
        await pilot.pause()

        expected_after_edit = {
            "create": "always",
            "modify": "always",
            "delete": "always",
            "rename": "always",
            "attrs": "never",
            "noise": "never",
        }
        # The pending dict must be the full, self-contained 6-key dict.
        assert screen._pending["tui.fsmon_event_visibility"] == expected_after_edit

        screen.action_save()
        await pilot.pause()

    # The save path (real SettingsController.save/_apply_setting, only the
    # disk-touching ConfigLoader stubbed out) must have applied the same
    # full dict -- "attrs" must still be "never", not reset to "always".
    assert preset_config.tui.fsmon_event_visibility == expected_after_edit
