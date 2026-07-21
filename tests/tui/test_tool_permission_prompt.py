"""Unit tests for sandroid.tui.widgets.tool_permission_prompt.

Uses Textual's own headless harness (``App.run_test()``) to mount the
widget standalone, mirroring the ``_ChatPanelHarness`` pattern already
established in ``tests/tui/test_chat_panel.py`` -- there is no bare
Widget-only test convention elsewhere in this repo yet, but ``run_test()``
is the standard, documented way to drive a widget in a test.
"""

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Button

from sandroid.ai.tools.registry import RiskTier, ToolSpec
from sandroid.tui.widgets.tool_permission_prompt import (
    ToolPermissionPrompt,
    _format_args_preview,
)


def _make_spec(name="install_apk", can_remember_choice=True, **overrides):
    defaults = {
        "name": name,
        "description": "Install an APK onto the device.",
        "parameters": {"type": "object", "properties": {}, "required": []},
        "func": lambda: None,
        "risk": RiskTier.REVERSIBLE,
        "can_remember_choice": can_remember_choice,
    }
    defaults.update(overrides)
    return ToolSpec(**defaults)


class _PromptHarness(App):
    """Minimal host app: just enough DOM for the prompt to mount standalone."""

    def __init__(self, spec, arguments, on_choice):
        super().__init__()
        self._spec = spec
        self._arguments = arguments
        self._on_choice = on_choice

    def compose(self) -> ComposeResult:
        yield ToolPermissionPrompt(self._spec, self._arguments, self._on_choice)


# -- button rendering ---------------------------------------------------


@pytest.mark.smoke
async def test_renders_three_buttons_when_can_remember_choice_true():
    spec = _make_spec(can_remember_choice=True)
    app = _PromptHarness(spec, {"apk_path": "/tmp/app.apk"}, lambda choice: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        ids = {b.id for b in app.query(Button)}
        assert ids == {"btn-once", "btn-always", "btn-never"}


@pytest.mark.smoke
async def test_renders_two_buttons_when_can_remember_choice_false():
    spec = _make_spec(can_remember_choice=False)
    app = _PromptHarness(spec, {}, lambda choice: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        ids = {b.id for b in app.query(Button)}
        assert ids == {"btn-once", "btn-never"}


@pytest.mark.smoke
async def test_never_button_label_is_decline_when_cannot_remember_choice():
    spec = _make_spec(can_remember_choice=False)
    app = _PromptHarness(spec, {}, lambda choice: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        never_button = app.query_one("#btn-never", Button)
        assert str(never_button.label) == "Decline"


@pytest.mark.smoke
async def test_never_button_label_is_never_when_can_remember_choice():
    spec = _make_spec(can_remember_choice=True)
    app = _PromptHarness(spec, {}, lambda choice: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        never_button = app.query_one("#btn-never", Button)
        assert str(never_button.label) == "Never"


# -- button presses call on_choice with the right string ----------------


@pytest.mark.smoke
async def test_run_once_button_calls_on_choice_with_once():
    choices = []
    spec = _make_spec(can_remember_choice=True)
    app = _PromptHarness(spec, {}, choices.append)
    async with app.run_test() as pilot:
        await pilot.click("#btn-once")
        assert choices == ["once"]


@pytest.mark.smoke
async def test_allow_always_button_calls_on_choice_with_always():
    choices = []
    spec = _make_spec(can_remember_choice=True)
    app = _PromptHarness(spec, {}, choices.append)
    async with app.run_test() as pilot:
        await pilot.click("#btn-always")
        assert choices == ["always"]


@pytest.mark.smoke
async def test_never_button_calls_on_choice_with_never():
    choices = []
    spec = _make_spec(can_remember_choice=True)
    app = _PromptHarness(spec, {}, choices.append)
    async with app.run_test() as pilot:
        await pilot.click("#btn-never")
        assert choices == ["never"]


@pytest.mark.smoke
async def test_decline_button_calls_on_choice_with_never_when_cannot_remember():
    """Even relabeled "Decline", the button's id/choice string stays "never"
    -- only the label changes for can_remember_choice=False tools.
    """
    choices = []
    spec = _make_spec(can_remember_choice=False)
    app = _PromptHarness(spec, {}, choices.append)
    async with app.run_test() as pilot:
        await pilot.click("#btn-never")
        assert choices == ["never"]


@pytest.mark.smoke
async def test_allow_always_button_absent_so_cannot_be_clicked():
    """Regression guard: with can_remember_choice=False there must be no
    #btn-always in the DOM at all (not just visually hidden).
    """
    spec = _make_spec(can_remember_choice=False)
    app = _PromptHarness(spec, {}, lambda choice: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        with pytest.raises(Exception):
            app.query_one("#btn-always", Button)


# -- args preview formatting (plan's exact inline spec) ------------------


def test_args_preview_is_sorted_json():
    preview = _format_args_preview({"b": 2, "a": 1})
    assert preview == '{"a": 1, "b": 2}'


def test_args_preview_truncates_long_arguments_with_ellipsis():
    long_value = "x" * 400
    preview = _format_args_preview({"payload": long_value})

    assert len(preview) == 301  # 300 chars + the trailing ellipsis char
    assert preview.endswith("…")
