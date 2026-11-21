"""Headless Textual Pilot tests for SettingsScreen.

Covers two independent additions to the Settings screen:

- The Monitor event-visibility rows: the 6 Select rows added to the General
  tab (``create``/``modify``/``delete``/``rename``/``attrs``/``noise``) and
  the ``on_select_changed`` save-path special-case for their
  ``setting-tui--monitor_event_visibility__<category>`` ids. The critical
  regression this guards against: ``SettingsController.save`` /
  ``update_config`` does a full REPLACE of the whole
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
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from pilot_helpers import until
from textual.app import App, ComposeResult
from textual.widgets import Input, RadioButton, Select, Static, Switch

from sandroid.config import SandroidConfig
from sandroid.core.adb import Adb
from sandroid.core.kprobe_tracer import KprobeTracer
from sandroid.core.toolbox import Toolbox
from sandroid.tui.screens.settings_screen import SettingsScreen
from sandroid.tui.widgets.chat_panel import ChatPanel

if TYPE_CHECKING:
    from pathlib import Path

_ALL_ALWAYS_NOISE_VERBOSE = {
    "create": "always",
    "modify": "always",
    "delete": "always",
    "rename": "always",
    "attrs": "always",
    "noise": "verbose",
}


@pytest.fixture
def live_config(tmp_path):
    """Install a config as the live ``get_config()`` singleton.

    ``SettingsController.save`` applies changes to the live singleton in
    place and persists only the changed keys to the config file in use --
    here a throwaway ``--config``-style file under ``tmp_path``.
    """
    from sandroid.config import set_config

    def _install(config: SandroidConfig) -> Path:
        cfg_file = tmp_path / "explicit.toml"
        cfg_file.write_text("")
        set_config(config, source_file=cfg_file)
        return cfg_file

    yield _install
    set_config(None)


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


async def test_title_and_switch_labels_are_plain_words() -> None:
    """No "=== Settings ===" decoration; switch states read "on"/"off" as in
    the header and every other dialog.
    """
    app = _MonitorSettingsHarness(SandroidConfig())
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        screen = app.screen
        title = str(screen.query_one("#settings-title").render())
        assert title.strip() == "Settings"
        states = {str(s.render()).strip() for s in screen.query(".switch-state")}
        assert states <= {"on", "off"} and states


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
    live_config,
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

    live_config(preset_config)

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

    # The save path (real SettingsController.save -> update_config, writing
    # to a tmp --config file) must have applied the same
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
        # Input.Changed bubbles from the Input to the screen: two hops.
        await until(
            pilot,
            lambda: screen._pending.get("device_paths.default_monitor_path")
            == "/sdcard/Download/",
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

    Save would refuse an out-of-range value anyway (``update_config``
    validates the whole config), but the field drops it at staging time so
    the rest of the pending changes still save. Schema bounds: [0.0, 5.0].
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
        release_probe.wait(timeout=10)
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

            assert probe_started.wait(timeout=10)
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
        # the daemon thread's probe lands via call_from_thread
        await until(
            pilot,
            lambda: (
                screen._pending.get("tui.monitor_backend") == "kprobe"
                and not kprobe_btn.disabled
                and "checking" not in str(kprobe_btn.label).lower()
            ),
        )

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


# -- Phase 5: auto_device_proxy + network_reset_after_snapshot are editable ----


@pytest.mark.asyncio
async def test_device_proxy_switch_and_network_reset_select_stage_keys() -> None:
    config = SandroidConfig()
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, SettingsScreen)

        switch = screen.query_one("#setting-mitmproxy--auto_device_proxy", Switch)
        assert switch.value is False
        switch.value = True
        await pilot.pause()
        assert screen._pending["mitmproxy.auto_device_proxy"] is True

        select = screen.query_one(
            "#setting-analysis--network_reset_after_snapshot", Select
        )
        assert select.value == "airplane"
        select.value = "svc"
        await pilot.pause()
        assert screen._pending["analysis.network_reset_after_snapshot"] == "svc"


@pytest.mark.asyncio
async def test_follow_the_app_switch_defaults_on_and_stages_the_key(
    monkeypatch,
) -> None:
    """``tui.monitor_follow_app`` (default on) has a switch in the Monitor tab."""
    from textual.widgets import Switch

    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    config = SandroidConfig()
    assert config.tui.monitor_follow_app is True
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        switch = screen.query_one("#setting-tui--monitor_follow_app", Switch)
        assert switch.value is True
        switch.value = False
        await pilot.pause()
        assert screen._pending["tui.monitor_follow_app"] is False


# -- N6-B3 / N6-V12: bounds, red field errors, focus, tabs, fit --------------


@pytest.mark.asyncio
async def test_negative_timeout_is_red_not_staged_and_blocks_save(
    monkeypatch,
) -> None:
    """A negative timeout shows a red field error and is never saved."""
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    app = _MonitorSettingsHarness(SandroidConfig())
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        field = screen.query_one("#setting-timeouts--adb_command", Input)
        field.value = "-5"
        await pilot.pause()
        assert "timeouts.adb_command" not in screen._pending
        assert field.has_class("-invalid")
        error = screen.query_one("#settings-error", Static)
        assert error.display
        assert "at least 1" in str(error.render())
        screen.action_save()
        await pilot.pause()
        assert app.screen is screen  # stays open on the bad field
        assert screen.focused is field
        # Blur keeps it red (Textual re-validates on blur).
        field.blur()
        await pilot.pause()
        assert field.has_class("-invalid")
        field.value = "45"
        await pilot.pause()
        assert screen._pending["timeouts.adb_command"] == 45
        assert not field.has_class("-invalid")
        assert not screen.query_one("#settings-error", Static).display


@pytest.mark.asyncio
async def test_unknown_avd_name_is_red_and_not_staged(monkeypatch) -> None:
    """A device name that is no AVD (a stray "0") is refused."""
    from sandroid.core import emulator

    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    monkeypatch.setattr(emulator, "known_avd_names", lambda: {"Dev4", "Pixel"})
    app = _MonitorSettingsHarness(SandroidConfig())
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause()
        screen = app.screen
        field = screen.query_one("#setting-emulator--device_name", Input)
        # The configured (default) name is not an AVD here: unchanged is fine.
        assert not field.has_class("-invalid")
        field.value = "0"
        await pilot.pause()
        assert "emulator.device_name" not in screen._pending
        assert "no AVD named '0'" in screen._invalid[field.id]
        field.value = "Dev4"
        await pilot.pause()
        assert screen._pending["emulator.device_name"] == "Dev4"
        assert field.id not in screen._invalid


@pytest.mark.asyncio
async def test_focus_starts_on_first_field_and_shift_arrows_switch_tabs(
    monkeypatch,
) -> None:
    """Deterministic focus (first field of the tab); Shift+Left/Right tabs."""
    from textual.widgets import TabbedContent

    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    for _ in range(2):  # the same on every open
        app = _MonitorSettingsHarness(SandroidConfig())
        async with app.run_test(size=(140, 50)) as pilot:
            await pilot.pause()
            await pilot.pause()
            screen = app.screen
            assert screen.focused is screen.query_one("#setting-log_level", Select)
            tabs = screen.query_one("#settings-tabs", TabbedContent)
            await pilot.press("shift+right")
            assert tabs.active == "tab-monitor"
            await pilot.press("shift+left", "shift+left")
            assert tabs.active == "tab-timeline"  # wraps


@pytest.mark.asyncio
async def test_footer_stays_on_screen_at_120x35(monkeypatch) -> None:
    """At 120x35 the body scrolls and the Save hint stays visible."""
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    app = _MonitorSettingsHarness(SandroidConfig())
    async with app.run_test(size=(120, 35)) as pilot:
        await pilot.pause()
        footer = app.screen.query_one(".settings-footer", Static)
        assert footer.region.height >= 1
        assert footer.region.bottom <= 35
        assert "Ctrl+S save" in str(footer.render())


def test_log_level_message_only_when_changed(caplog) -> None:
    """Saving an unchanged log level does not log "Log level changed"."""
    import logging

    from sandroid.tui.controllers.settings_controller import SettingsController

    root = logging.getLogger()
    old = root.level
    try:
        root.setLevel(logging.INFO)
        controller = SettingsController(SimpleNamespace())
        with caplog.at_level(logging.INFO, logger="sandroid"):
            controller.apply_log_level("INFO")
            assert "Log level changed" not in caplog.text
            controller.apply_log_level("DEBUG")
            assert "Log level changed to DEBUG" in caplog.text
    finally:
        root.setLevel(old)


@pytest.mark.asyncio
async def test_a_focused_switch_is_visibly_highlighted(monkeypatch) -> None:
    monkeypatch.setattr(KprobeTracer, "cached_availability", lambda: True)
    app = _MonitorSettingsHarness(SandroidConfig())
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause()
        switch = app.screen.query_one("#setting-emulator--avd_headless", Switch)
        before = switch.styles.background
        switch.focus()
        await pilot.pause()
        assert switch.has_focus
        assert switch.styles.background != before


async def test_persona_topup_switch_stages_and_saves_the_world_key(
    live_config,
) -> None:
    """``[world] persona_topup`` was reachable only by editing the TOML."""
    from textual.widgets import Switch

    from sandroid.world import persona

    config = SandroidConfig()
    assert config.world.persona_topup is True
    assert "persona snapshot" in (
        type(config.world).model_fields["persona_topup"].description
    )
    cfg_file = live_config(config)
    app = _MonitorSettingsHarness(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        screen = app.screen
        switch = screen.query_one("#setting-world--persona_topup", Switch)
        assert switch.value is True
        switch.value = False
        await pilot.pause()
        assert screen._pending["world.persona_topup"] is False
        screen.action_save()
        await pilot.pause()
    assert config.world.persona_topup is False
    assert persona.topup_enabled() is False
    assert "persona_topup = false" in cfg_file.read_text()


def test_unknown_world_keys_survive_the_schema_section() -> None:
    from sandroid.world import generator

    config = SandroidConfig(world={"email_domain": "example.org", "x": 1})
    assert config.world.persona_topup is True
    assert config.world.email_domain == "example.org"
    from sandroid.config import set_config

    set_config(config)
    try:
        assert generator.configured_email_domain() == "example.org"
    finally:
        set_config(None)
