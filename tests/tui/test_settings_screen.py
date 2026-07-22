"""Headless Textual Pilot tests for SettingsScreen.

Covers two independent additions to the Settings screen:

- The Monitor event-visibility rows: the 6 Select rows added to the General
  tab (``create``/``modify``/``delete``/``rename``/``attrs``/``noise``) and
  the ``on_select_changed`` save-path special-case for their
  ``setting-tui--monitor_event_visibility__<category>`` ids. The critical
  regression this guards against: ``SettingsController.save`` /
  ``_apply_setting`` does a full ``setattr`` REPLACE of the whole
  ``monitor_event_visibility`` dict, not a merge. If the special-case handler
  only ever inserted the one changed category into a fresh dict, saving
  would silently wipe the other 5 categories back to nothing (or to their
  schema defaults, whichever a naive implementation happened to default
  to). The merge-safety test below seeds a *second*, non-default category
  before touching a *first* one, so a regression to that bug would be
  caught.

- Two real bugs found in the AI Chat tab (cramped/misaligned layout, and
  toggles not taking effect until Save). Uses the same ``App.run_test()``
  headless harness as ``test_chat_panel.py`` (see that file's module
  docstring for why this is the right tool here).

The background Frida-version-fetch thread that ``SettingsScreen.on_mount``
starts is stubbed to a no-op in all tests here -- it does real network I/O
(GitHub tag listing) via a daemon thread and is unrelated to what this file
covers.
"""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, RadioButton, Select, Static, Switch

from sandroid.config import SandroidConfig
from sandroid.core.adb import Adb
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.core.toolbox import Toolbox
from sandroid.tui.screens.settings_screen import SettingsScreen
from sandroid.tui.widgets.chat_panel import ChatPanel

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


class _MonitorSettingsHarness(App):
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


class _ChatSettingsHarness(App):
    """Host app mirroring the real shape: a base screen holding ChatPanel
    (standing in for MainScreen), with SettingsScreen pushed on top as a
    modal -- exactly the screen_stack shape ``SettingsScreen._refresh_chat_panel``
    has to walk in production (ChatPanel is *not* on the active/top screen).
    """

    def __init__(self) -> None:
        super().__init__()
        # Mirrors SandroidTUI.sandroid_config -- SettingsScreen._get_config()
        # prefers this over get_config()'s file-backed singleton, so the
        # tab's *displayed* values are deterministic regardless of any real
        # config file on the test machine.
        self.sandroid_config = SandroidConfig()

    def compose(self) -> ComposeResult:
        yield ChatPanel(id="chat-panel")


@pytest.fixture(autouse=True)
def _no_frida_version_fetch(monkeypatch):
    """Prevent the real background network-fetch thread from starting."""
    monkeypatch.setattr(SettingsScreen, "_fetch_frida_versions", lambda self: None)


def _visibility_select(screen: SettingsScreen, category: str) -> Select:
    return screen.query_one(
        f"#setting-tui--monitor_event_visibility__{category}", Select
    )


# -- Monitor event-visibility rows ---------------------------------------------


@pytest.mark.asyncio
async def test_compose_renders_default_visibility_selects() -> None:
    """Schema-default config: 5 categories 'always', noise 'verbose'."""
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
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
    config.tui.monitor_event_visibility = {
        "create": "never",
        "modify": "verbose",
        "delete": "always",
        "rename": "never",
        "attrs": "verbose",
        "noise": "never",
    }
    app = _MonitorSettingsHarness(config)
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
    preset_config.tui.monitor_event_visibility = {
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

    app = _MonitorSettingsHarness(preset_config)
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
        assert screen._pending["tui.monitor_event_visibility"] == expected_after_edit

        screen.action_save()
        await pilot.pause()

    # The save path (real SettingsController.save/_apply_setting, only the
    # disk-touching ConfigLoader stubbed out) must have applied the same
    # full dict -- "attrs" must still be "never", not reset to "always".
    assert preset_config.tui.monitor_event_visibility == expected_after_edit


# -- Bug A: cramped/misaligned AI Chat tab layout ---------------------------


@pytest.mark.smoke
async def test_ai_chat_help_text_spans_full_row_with_gap_before_next_row():
    """Regression test for the reported layout bug: the help-text ``Static``
    following "Show Verbose Thinking:" used to reuse ``.setting-label``
    (``width: 30``, right-aligned, no margin) -- the class meant for short
    row labels, not wrapped paragraphs. That squeezed the paragraph into a
    narrow right-aligned column tall enough (7 wrapped lines) to butt
    directly against "Show Chat Mascot:" with zero gap. The fix is a
    dedicated ``.setting-help`` class: full row width (so it wraps like a
    normal paragraph, not a cramped column) and its own margin-bottom (so a
    visible gap always separates it from the next row).
    """
    app = _ChatSettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()
        screen.query_one("#settings-tabs").active = "tab-ai-chat"
        await pilot.pause()

        pane = screen.query_one("#tab-ai-chat")
        rows = pane.query(".setting-row")
        statics = [w for w in pane.walk_children() if isinstance(w, Static)]
        help_texts = [w for w in statics if "setting-help" in w.classes]

        assert len(rows) == 2
        assert len(help_texts) == 2

        verbose_row, mascot_row = rows[0], rows[1]
        thinking_help = help_texts[0]

        # Full row width, not the narrow 30-column label width.
        assert thinking_help.region.width == verbose_row.region.width

        # A real gap: the help text's bottom edge must sit strictly above
        # the next row's top edge (the old bug had them touch exactly, 0
        # rows apart).
        gap = mascot_row.region.y - thinking_help.region.bottom
        assert gap >= 1, f"expected a visible gap, got {gap} rows"


# -- Bug B: AI Chat toggles don't take effect immediately -------------------


@pytest.mark.smoke
async def test_toggle_show_chat_mascot_immediately_hides_live_mascot(monkeypatch):
    """Core regression test: flipping "Show Chat Mascot" off must hide the
    mascot on an already-mounted, idle ``ChatPanel`` immediately -- with NO
    other event (chat turn, header refresh, etc.) happening in between.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _ChatSettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)
        assert mascot.display is True  # sanity: visible before any toggle

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        assert switch.value is True

        switch.toggle()  # the ONLY thing that happens -- no chat activity
        await pilot.pause()

        # The live config object ChatPanel actually reads was updated...
        assert ai_cfg.show_chat_mascot is False
        # ...and the already-mounted ChatPanel repainted without being told
        # about it any other way.
        assert mascot.display is False


@pytest.mark.smoke
async def test_toggle_show_chat_mascot_back_on_immediately_shows_it(monkeypatch):
    """Symmetric case: toggling back on must re-show the mascot immediately."""
    ai_cfg = SimpleNamespace(show_chat_mascot=False, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _ChatSettingsHarness()
    # The Switch's *displayed* value comes from the settings screen's own
    # config (self.app.sandroid_config), a separate object from Toolbox.config
    # on purpose (that's the crux of the bug) -- match it here so the switch
    # actually starts unchecked, matching ai_cfg's starting state.
    app.sandroid_config.ai.show_chat_mascot = False
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)
        assert mascot.display is False

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        assert switch.value is False

        switch.toggle()
        await pilot.pause()

        assert ai_cfg.show_chat_mascot is True
        assert mascot.display is True


async def test_toggle_show_verbose_thinking_applies_to_live_config_immediately(
    monkeypatch,
):
    """``show_verbose_thinking`` has no on-screen content that needs a
    retroactive repaint (confirmed by reading ``chat_panel.py``: it's only
    read once, at the moment a reasoning phase ends via
    ``_finalize_reasoning_only``) -- but the live config write itself must
    still happen immediately, not wait for Save, so the very next reasoning
    phase already honors the new value.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _ChatSettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_verbose_thinking", Switch)
        switch.toggle()
        await pilot.pause()

        assert ai_cfg.show_verbose_thinking is True


@pytest.mark.smoke
async def test_cancel_reverts_live_mascot_toggle_preview(monkeypatch):
    """Mirrors the theme radio's preview/revert-on-cancel contract: a switch
    applied live for preview but never saved must not silently stick.
    """
    ai_cfg = SimpleNamespace(show_chat_mascot=True, show_verbose_thinking=False)
    monkeypatch.setattr(Toolbox, "config", SimpleNamespace(ai=ai_cfg), raising=False)

    app = _ChatSettingsHarness()
    async with app.run_test(size=(100, 50)) as pilot:
        mascot = app.query_one("#chat-mascot", Static)

        screen = SettingsScreen()
        await app.push_screen(screen)
        await pilot.pause()

        switch = screen.query_one("#setting-ai--show_chat_mascot", Switch)
        switch.toggle()
        await pilot.pause()
        assert ai_cfg.show_chat_mascot is False
        assert mascot.display is False

        screen.action_cancel()
        await pilot.pause()

        assert ai_cfg.show_chat_mascot is True
        assert mascot.display is True


def test_on_switch_changed_still_stages_into_pending():
    """Non-regression: the live-apply path must not replace the existing
    stage-into-_pending behavior Save relies on for persistence.
    """
    from textual.widgets import Switch as SwitchWidget

    screen = SettingsScreen()
    switch = SwitchWidget(value=False, id="setting-ai--show_chat_mascot")
    event = SwitchWidget.Changed(switch, False)
    screen.on_switch_changed(event)

    assert screen._pending == {"ai.show_chat_mascot": False}


# -- Monitor Source (backend) selector + default path -------------------------


@pytest.mark.asyncio
async def test_kprobe_disabled_and_selection_lands_on_fsmon_when_unavailable(
    monkeypatch,
) -> None:
    """Decision C: a definitive ``False`` kprobe verdict greys kprobe, labels it
    "unavailable", and flips the visible selection to fsmon -- WITHOUT persisting
    fsmon over the saved kprobe preference.

    The schema default backend is ``kprobe``; on a device whose kernel lacks
    kprobe support the Source selector must show fsmon (the source that will
    actually run) rather than a greyed-but-checked kprobe. But because kprobe
    availability is per-device and ``tui.monitor_backend`` is a global
    preference, the auto-flip must NOT stage ``fsmon`` into ``_pending`` (a
    later Ctrl+S would otherwise clobber the kprobe preference for future
    capable devices).
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: False)
    config = SandroidConfig()
    assert config.tui.monitor_backend == "kprobe"  # sanity: schema default
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        kprobe_btn = screen.query_one("#backend-kprobe", RadioButton)
        fsmon_btn = screen.query_one("#backend-fsmon", RadioButton)

        assert kprobe_btn.disabled is True
        assert fsmon_btn.value is True
        assert kprobe_btn.value is False
        # Persistent, always-visible "unavailable" signal on the label.
        assert "unavailable" in str(kprobe_btn.label).lower()
        # Preference preserved: the auto-flip is visual-only, never staged.
        assert "tui.monitor_backend" not in screen._pending


@pytest.mark.asyncio
async def test_warmed_unavailable_verdict_disables_without_persisting(
    monkeypatch,
) -> None:
    """An off-thread warm-up that resolves to unavailable must disable+label
    kprobe and flip to fsmon WITHOUT staging fsmon.

    This guards the ``cached_availability() is None`` vs ``kprobe_supported()
    is False`` inconsistency: on a device where the self-check is inconclusive
    the cache stays ``None`` while the probe boolean is ``False``. The warm-up
    keys off the boolean, so a known-unusable kprobe is correctly greyed
    instead of left selectable.
    """
    # None cached + no device -> on_mount leaves kprobe available (no auto
    # warm-up thread), so we can drive _apply_warmed_availability deterministically.
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: None)
    monkeypatch.setattr(Adb, "get_target_device", lambda: "")
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        kprobe_btn = screen.query_one("#backend-kprobe", RadioButton)
        assert kprobe_btn.disabled is False  # None+no-device -> selectable

        # Simulate the warm-up probe resolving to "unavailable".
        screen._apply_warmed_availability(False)
        await pilot.pause()

        fsmon_btn = screen.query_one("#backend-fsmon", RadioButton)
        assert kprobe_btn.disabled is True
        assert "unavailable" in str(kprobe_btn.label).lower()
        assert fsmon_btn.value is True
        assert kprobe_btn.value is False
        assert "tui.monitor_backend" not in screen._pending


@pytest.mark.asyncio
async def test_selecting_fsmon_stages_fsmon(monkeypatch) -> None:
    """Interactively picking fsmon stages ``"fsmon"``."""
    # kprobe available -> on_mount leaves the default selection untouched.
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        screen.query_one("#backend-fsmon", RadioButton).value = True
        await pilot.pause()

        assert screen._pending["tui.monitor_backend"] == "fsmon"


@pytest.mark.asyncio
async def test_default_monitor_path_input_stages_key(monkeypatch) -> None:
    """The default-path Input stages ``device_paths.default_monitor_path``."""
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        path_input = screen.query_one(
            "#setting-device_paths--default_monitor_path", Input
        )
        path_input.value = "/sdcard/Download/"
        await pilot.pause()

        assert (
            screen._pending["device_paths.default_monitor_path"] == "/sdcard/Download/"
        )


@pytest.mark.asyncio
async def test_empty_default_monitor_path_is_not_staged(monkeypatch) -> None:
    """An empty default-path must not be staged (and drops any prior value).

    ``DevicePathsConfig.validate_non_empty_path`` runs only at construction,
    so persisting ``""`` would break the *next* config load.
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        path_input = screen.query_one(
            "#setting-device_paths--default_monitor_path", Input
        )
        path_input.value = "/data/local/tmp/"
        await pilot.pause()
        assert (
            screen._pending["device_paths.default_monitor_path"] == "/data/local/tmp/"
        )

        # Blanking the field must drop the previously-staged value, not
        # persist an empty string.
        path_input.value = ""
        await pilot.pause()
        assert "device_paths.default_monitor_path" not in screen._pending


@pytest.mark.asyncio
async def test_out_of_range_monitor_buffer_interval_is_not_staged(
    monkeypatch,
) -> None:
    """An out-of-schema-range buffer interval must not be staged.

    ``TUIConfig`` has no ``validate_assignment``, so ``_apply_setting``'s
    plain ``setattr`` on save would silently accept an invalid value and only
    fail on the *next* config load (where ``get_config()``'s broad exception
    fallback resets the WHOLE config to defaults). Schema bounds: [0.0, 5.0].
    Mirrors the blank-default-path guard: an invalid value DROPS any pending
    override entirely (falling back to the on-disk value on save), the same
    behavior as blanking the default-path Input.
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        buf_input = screen.query_one("#setting-tui--monitor_buffer_interval", Input)
        buf_input.value = "2.5"
        await pilot.pause()
        assert screen._pending["tui.monitor_buffer_interval"] == 2.5

        # Out of range (> 5.0) drops the pending override entirely.
        buf_input.value = "999"
        await pilot.pause()
        assert "tui.monitor_buffer_interval" not in screen._pending


@pytest.mark.asyncio
async def test_out_of_range_monitor_max_lines_is_not_staged(monkeypatch) -> None:
    """An out-of-schema-range max-lines value must not be staged.

    Schema bounds: [50, 10000]. Mirrors the blank-default-path guard: an
    invalid value DROPS any pending override entirely.
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        lines_input = screen.query_one("#setting-tui--monitor_max_lines", Input)
        lines_input.value = "1000"
        await pilot.pause()
        assert screen._pending["tui.monitor_max_lines"] == 1000

        # Below the minimum (50) drops the pending override entirely.
        lines_input.value = "1"
        await pilot.pause()
        assert "tui.monitor_max_lines" not in screen._pending


@pytest.mark.asyncio
async def test_interactive_kprobe_select_shows_checking_before_probe(
    monkeypatch,
) -> None:
    """Selecting kprobe with an unconfirmed (``None``) verdict must show
    "checking..." (disabled) BEFORE the off-thread probe starts -- mirroring
    ``refresh_backend_availability``'s ordering -- so the user can't persist
    an unverified ``kprobe`` mid-probe. The probe itself is blocked on an
    Event so the test can observe the intermediate "checking" state.
    """
    probe_started = threading.Event()
    release_probe = threading.Event()

    def _blocking_probe():
        probe_started.set()
        release_probe.wait(timeout=5)
        return True

    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: None)
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", _blocking_probe)
    monkeypatch.setattr(Adb, "get_target_device", lambda: "emulator-5556")
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    try:
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SettingsScreen)

            kprobe_btn = screen.query_one("#backend-kprobe", RadioButton)
            fsmon_btn = screen.query_one("#backend-fsmon", RadioButton)
            fsmon_btn.value = True
            await pilot.pause()

            kprobe_btn.value = True
            await pilot.pause()

            assert probe_started.wait(timeout=2)
            # Mid-probe: disabled + "checking" label, not the plain label.
            assert kprobe_btn.disabled is True
            assert "checking" in str(kprobe_btn.label).lower()
    finally:
        release_probe.set()


@pytest.mark.asyncio
async def test_interactive_kprobe_select_restores_available_on_success(
    monkeypatch,
) -> None:
    """A confirmed-available interactive select-probe restores the plain
    "available" state (not left stuck reading "checking...").
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: None)
    monkeypatch.setattr(KprobeTracer, "kprobe_supported", lambda: True)
    monkeypatch.setattr(Adb, "get_target_device", lambda: "emulator-5556")
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        kprobe_btn = screen.query_one("#backend-kprobe", RadioButton)
        fsmon_btn = screen.query_one("#backend-fsmon", RadioButton)
        fsmon_btn.value = True
        await pilot.pause()

        kprobe_btn.value = True
        await pilot.pause(0.2)  # let the daemon thread + call_from_thread land

        assert kprobe_btn.disabled is False
        assert "checking" not in str(kprobe_btn.label).lower()
        assert "unavailable" not in str(kprobe_btn.label).lower()
        assert screen._pending["tui.monitor_backend"] == "kprobe"


@pytest.mark.asyncio
async def test_interactive_kprobe_select_with_no_device_skips_checking(
    monkeypatch,
) -> None:
    """With no device connected, selecting kprobe on an unconfirmed verdict
    stages it optimistically WITHOUT entering "checking" (mirrors
    ``refresh_backend_availability``'s no-device policy -- nothing to probe).
    """
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: None)
    monkeypatch.setattr(Adb, "get_target_device", lambda: "")
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        kprobe_btn = screen.query_one("#backend-kprobe", RadioButton)
        fsmon_btn = screen.query_one("#backend-fsmon", RadioButton)
        fsmon_btn.value = True
        await pilot.pause()

        kprobe_btn.value = True
        await pilot.pause()

        assert kprobe_btn.disabled is False
        assert "checking" not in str(kprobe_btn.label).lower()
        assert screen._pending["tui.monitor_backend"] == "kprobe"
