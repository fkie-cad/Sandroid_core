"""Unit tests for sandroid.tui.widgets.tool_permission_prompt.

The card is mounted standalone in a bare Textual ``App`` (``run_test()``).
Keyboard tests pass ``input_grace_s=0`` so keys act immediately; one test
checks the grace period itself.
"""

import pytest
from textual.app import App, ComposeResult
from textual.widgets import Input, Label, Static

from sandroid.ai.tool_permissions import ApprovalRequest, Decision
from sandroid.ai.tools.registry import RiskTier, ToolSpec
from sandroid.tui.widgets.tool_permission_prompt import (
    _DESCRIPTION_MAX_LEN,
    ApprovalOption,
    ToolPermissionPrompt,
    _format_args_preview,
    _truncate,
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


class _Harness(App):
    """Minimal host app: just enough DOM for the card to mount standalone."""

    def __init__(self, *args, **kwargs):
        super().__init__()
        self._args = args
        self._kwargs = kwargs

    def compose(self) -> ComposeResult:
        yield ToolPermissionPrompt(*self._args, **self._kwargs)


def _new(decisions, **kw):
    """A card on the new contract (on_decision), keys active at once."""
    kw.setdefault("input_grace_s", 0)
    spec = kw.pop("spec", _make_spec())
    return _Harness(spec, kw.pop("arguments", {}), on_decision=decisions.append, **kw)


def _ids(app):
    return [b.id for b in app.query(ApprovalOption)]


def _label(app, button_id):
    return app.query_one(f"#{button_id}", ApprovalOption).label


def _highlighted(app):
    return [o.id for o in app.query(ApprovalOption) if o.has_class("-highlighted")]


# -- rendering -------------------------------------------------------------


@pytest.mark.smoke
async def test_three_options_with_rule_description_and_agent_label():
    app = _new([], agent_label="operator a-op-3f9c")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert _ids(app) == ["btn-once", "btn-always", "btn-never"]
        assert _label(app, "btn-once") == "1  Yes"
        assert _label(app, "btn-always") == "2  Yes, don't ask again for Install APK"
        assert _label(app, "btn-never") == "3  No, and tell it what to do instead…"
        title = str(app.query_one(".tool-permission-title", Label).render())
        assert title == "operator a-op-3f9c wants to run Install APK"
        tier = str(app.query_one(".tool-permission-tier", Label).render())
        assert tier == "reversible"
        assert app.query_one(ToolPermissionPrompt).has_focus


@pytest.mark.smoke
async def test_argument_dependent_tool_without_key_has_no_remember_option():
    app = _new([], spec=_make_spec(can_remember_choice=False))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert _ids(app) == ["btn-once", "btn-never"]
        assert _label(app, "btn-never").startswith("2  No")


@pytest.mark.smoke
async def test_argument_dependent_tool_with_key_names_the_argument():
    app = _new(
        [],
        spec=_make_spec(name="kill_process", can_remember_choice=False),
        arguments={"package": "com.example.app"},
        permission_key="package",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        assert _label(app, "btn-always") == (
            "2  Yes, don't ask again for Kill Process with package = com.example.app"
        )
        assert app.query_one(ToolPermissionPrompt).suggested_rule == (
            "kill_process(package=com.example.app)"
        )


@pytest.mark.smoke
async def test_built_from_a_broker_request():
    request = ApprovalRequest(
        request_id="ap-1",
        agent_id="a-op-1",
        agent_label="operator a-op-1",
        tool="clear_app_data",
        args={"package": "com.x"},
        risk=RiskTier.CONSEQUENTIAL,
        suggested_rule="clear_app_data(package=com.x)",
        description="Wipe the app's data.",
    )
    decisions = []
    app = _Harness(request=request, on_decision=decisions.append, input_grace_s=0)
    async with app.run_test() as pilot:
        await pilot.pause()
        title = str(app.query_one(".tool-permission-title", Label).render())
        assert title == "operator a-op-1 wants to run Clear App Data"
        assert app.query_one(".tool-permission-tier").has_class("-consequential")
        message = str(app.query_one(".tool-permission-message", Label).render())
        assert "Wipe the app's data." in message
        assert "com.x" in message
        await pilot.press("2")
        assert decisions == [
            Decision("always", remembered_rule="clear_app_data(package=com.x)")
        ]


# -- keys ------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.parametrize(("key", "choice"), [("1", "once"), ("2", "always")])
async def test_number_keys(key, choice):
    decisions = []
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press(key)
        assert [d.choice for d in decisions] == [choice]
        await pilot.press("1")  # answered once only
        assert len(decisions) == 1


@pytest.mark.smoke
async def test_arrows_and_enter():
    decisions = []
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("down", "down", "down", "up", "enter")
        assert decisions == [Decision("always", remembered_rule="install_apk")]


@pytest.mark.smoke
async def test_escape_is_no():
    decisions = []
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("escape")
        assert decisions == [Decision("no")]


@pytest.mark.smoke
async def test_option_three_reveals_note_and_enter_submits_it():
    decisions = []
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        note = app.query_one("#tool-permission-note", Input)
        assert not note.display
        await pilot.press("3")
        await pilot.pause()
        assert decisions == []
        assert note.display
        assert note.has_focus
        await pilot.press(*"use 1 adb")
        await pilot.press("enter")
        assert decisions == [Decision("no", note="use 1 adb")]


async def test_pull_tool_note_says_other_pull_tools_stay_blocked():
    """R2-U1: a No to a pull tool blocks the others this turn unless the
    note names one; the note input says so.
    """
    app = _new([], spec=_make_spec("pull_path"))
    async with app.run_test() as pilot:
        await pilot.pause()
        note = app.query_one("#tool-permission-note", Input)
        assert "other pull tools stay blocked this turn" in note.placeholder
        assert "unless named here" in note.placeholder
    plain = _new([])
    async with plain.run_test() as pilot:
        await pilot.pause()
        note = plain.query_one("#tool-permission-note", Input)
        assert "blocked" not in note.placeholder


@pytest.mark.smoke
async def test_empty_note_is_plain_no_and_escape_keeps_typed_note():
    decisions = []
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("3", "enter")
        assert decisions == [Decision("no")]
    decisions.clear()
    app = _new(decisions)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("3", "x", "escape")
        assert decisions == [Decision("no", note="x")]


@pytest.mark.smoke
async def test_keys_are_ignored_during_grace_period_but_clicks_work():
    decisions = []
    app = _new(decisions, input_grace_s=60)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("1", "enter")
        assert decisions == []
        await pilot.click("#btn-once")
        assert decisions == [Decision("once")]


def test_action_cancel_is_sync():
    import inspect

    assert not inspect.iscoroutinefunction(ToolPermissionPrompt.action_cancel)


# -- look: one selected option, distinct note state ----------------------------


@pytest.mark.smoke
async def test_only_the_selected_option_is_highlighted_and_marked():
    app = _new([])
    async with app.run_test() as pilot:
        await pilot.pause()
        assert _highlighted(app) == ["btn-once"]
        options = list(app.query(ApprovalOption))
        backgrounds = [o.styles.background for o in options]
        assert backgrounds[0] != backgrounds[1]
        assert backgrounds[1] == backgrounds[2]  # the others stay plain
        # The highlight bar alone marks the selection: no glyph on any row.
        assert all("›" not in str(o.render()) for o in options)
        assert str(options[0].render()) == options[0].label
        await pilot.press("down")
        assert _highlighted(app) == ["btn-always"]
        assert str(options[1].render()) == options[1].label
        assert options[1].styles.background != options[0].styles.background


@pytest.mark.smoke
async def test_note_state_is_visually_distinct():
    app = _new([])
    async with app.run_test() as pilot:
        await pilot.pause()
        card = app.query_one(ToolPermissionPrompt)
        hint = app.query_one(".tool-permission-hint", Label)
        before = str(hint.render())
        await pilot.press("3")
        await pilot.pause()
        assert card.noting
        assert _highlighted(app) == ["btn-never"]
        assert str(hint.render()) != before
        assert "note" in str(hint.render())


@pytest.mark.smoke
async def test_stray_letters_are_swallowed_while_the_card_has_focus():
    """A word typed on (meant for the chat input) never reaches App hotkeys."""
    fired = []

    class _App(_Harness):
        BINDINGS = [("s", "hotkey", "Hotkey")]

        def action_hotkey(self):
            fired.append("s")

    decisions = []
    app = _App(_make_spec(), {}, on_decision=decisions.append, input_grace_s=0)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one(ToolPermissionPrompt).has_focus
        await pilot.press("s", "x")
        assert fired == []
        assert decisions == []
        await pilot.press("1")
        assert [d.choice for d in decisions] == ["once"]


@pytest.mark.smoke
async def test_does_not_take_focus_from_outside_its_parent():
    from textual.containers import Vertical

    class _App(App):
        def compose(self):
            yield Input(id="elsewhere")
            yield Vertical(id="panel")

    app = _App()
    async with app.run_test() as pilot:
        app.query_one("#elsewhere", Input).focus()
        await pilot.pause()
        card = ToolPermissionPrompt(_make_spec(), {}, input_grace_s=0)
        await app.query_one("#panel").mount(card)
        await pilot.pause()
        await pilot.pause()
        assert app.query_one("#elsewhere", Input).has_focus
        assert not card.may_take_focus()
        await pilot.press("enter")
        assert not card.decided


@pytest.mark.smoke
@pytest.mark.parametrize(
    "value",
    [
        "ls [Black on black]; rm -rf /data/data/com.victim",
        "[A-Z]{3}",
        "[/][#000000 on #000000]hidden[/]",
        "[bold]x[/bold] [x] [/]",
    ],
)
async def test_model_text_is_never_parsed_as_markup(value):
    """``rich.markup.escape`` does not match Textual 8's parser
    (escape_probe2): ``[Black on black]`` hid text, ``[A-Z]`` vanished.
    """
    request = ApprovalRequest(
        request_id="ap-9",
        agent_id="a-op-1",
        agent_label=f"agent {value}",
        tool="run_shell",
        args={"command": value},
        risk=RiskTier.CONSEQUENTIAL,
        suggested_rule=None,
        description=f"Runs {value}.",
    )
    app = _Harness(request=request, on_decision=lambda d: None, input_grace_s=0)
    async with app.run_test() as pilot:
        await pilot.pause()
        message = app.query_one(".tool-permission-message", Label).render()
        title = app.query_one(".tool-permission-title", Label).render()
        assert value in str(title)
        assert f"Runs {value}." in str(message)
        # No span hides anything (no style other than the card's own).
        for span in message.spans:
            assert "on #000000" not in str(span.style)


def test_needs_spec_or_request():
    with pytest.raises(ValueError):
        ToolPermissionPrompt()


# -- args preview / helpers --------------------------------------------------------


def test_exported_helpers():
    assert _DESCRIPTION_MAX_LEN == 150
    assert _truncate("abcdef", 3) == "abc…"
    assert _truncate("ab", 3) == "ab"


def test_args_preview_is_sorted_json():
    assert _format_args_preview({"b": 2, "a": 1}) == '{"a": 1, "b": 2}'


def test_args_preview_truncates_long_arguments_with_ellipsis():
    preview = _format_args_preview({"payload": "x" * 400})
    assert len(preview) == 301
    assert preview.endswith("…")


@pytest.mark.smoke
async def test_long_arguments_are_flagged_and_shown_in_full():
    tail = "; touch /tmp/PWNED #"
    arguments = {"path": "/data/" + "a" * 400 + tail}
    app = _Harness(_make_spec(), arguments, on_decision=lambda d: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        message = str(app.query_one(".tool-permission-message", Label).render())
        assert "TRUNCATED" in message
        full = str(app.query_one("#tool-permission-args", Static).render())
        assert tail in full


@pytest.mark.smoke
async def test_markup_in_arguments_and_rule_is_escaped():
    arguments = {"name": "[/][#000000 on #000000]hidden[/]"}
    app = _new(
        [],
        spec=_make_spec(name="kill_process", can_remember_choice=False),
        arguments={**arguments, "package": "[b]x[/b]"},
        permission_key="package",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        message = str(app.query_one(".tool-permission-message", Label).render())
        assert "[/][#000000 on #000000]hidden[/]" in message
        assert not app.query("#tool-permission-args")
        assert "[b]x[/b]" in _label(app, "btn-always")


@pytest.mark.smoke
async def test_omitted_package_shows_resolved_spotlight_app(monkeypatch):
    from sandroid import services

    class _Spot:
        @staticmethod
        def get_effective_package():
            return "com.example.target"

    monkeypatch.setattr(services, "get_spotlight_service", _Spot)
    spec = _make_spec(
        name="enable_app_proxy",
        parameters={
            "type": "object",
            "properties": {"package": {"type": "string"}},
            "required": [],
        },
    )
    app = _Harness(spec, {}, on_decision=lambda d: None)
    async with app.run_test() as pilot:
        await pilot.pause()
        message = str(app.query_one(".tool-permission-message", Label).render())
        assert "com.example.target" in message
