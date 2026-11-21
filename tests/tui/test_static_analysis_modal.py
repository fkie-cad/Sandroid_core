"""The ``a`` dialog (StaticAnalysisModal) and how StaticAnalysis remembers it.

- ``p`` switches profile, ``t``/``s``/``v`` switch options, Enter returns the
  choice, Esc returns ``None``.
- States are plain words; no symbols anywhere in the dialog text.
- StaticAnalysis preselects the remembered choice and remembers a confirmed
  one in ``tui_state.json``; a cancelled dialog remembers nothing.
"""

from __future__ import annotations

import re

import pytest
from pilot_helpers import settle, until
from textual.app import App
from textual.widgets import Label, Static

from sandroid.analysis import static_analysis
from sandroid.config.ui_state import load_ui_state, update_ui_state
from sandroid.tui.modals.static_analysis_modal import (
    DEFAULT_STATIC_ANALYSIS_CHOICE,
    StaticAnalysisModal,
    normalize_choice,
)


class _Harness(App):
    def __init__(self, modal):
        super().__init__()
        self.modal = modal
        self.result = "pending"

    def on_mount(self) -> None:
        self.push_screen(self.modal, callback=self._done)

    def _done(self, result) -> None:
        self.result = result


def _text(app) -> str:
    parts = []
    for widget in app.screen.query(Static):
        rendered = widget.render()
        parts.append(getattr(rendered, "plain", str(rendered)))
    for widget in app.screen.query(Label):
        rendered = widget.render()
        parts.append(getattr(rendered, "plain", str(rendered)))
    return "\n".join(parts)


@pytest.mark.asyncio
async def test_keys_change_the_choice_and_enter_returns_it() -> None:
    app = _Harness(StaticAnalysisModal(choice=None, target="org.example.app"))
    async with app.run_test() as pilot:
        await settle(pilot)
        text = _text(app)
        assert "org.example.app" in text
        assert "generic" in text
        assert "privacy" in text
        for key in ("p", "t", "s", "v"):
            await pilot.press(key)
        await pilot.press("enter")
        await until(pilot, lambda: app.result != "pending")
    assert app.result == {
        "profile": "privacy",
        "trackers": False,
        "security": False,
        "verbose": True,
    }


@pytest.mark.asyncio
async def test_escape_cancels() -> None:
    app = _Harness(StaticAnalysisModal(choice={"profile": "privacy"}))
    async with app.run_test() as pilot:
        await settle(pilot)
        await pilot.press("escape")
        await until(pilot, lambda: app.result != "pending")
    assert app.result is None


@pytest.mark.asyncio
async def test_dialog_text_has_no_symbols() -> None:
    app = _Harness(StaticAnalysisModal(choice={"profile": "privacy"}))
    async with app.run_test() as pilot:
        await settle(pilot)
        text = _text(app)
    # N6-V6: the profile is marked with a dot, no "selected" word dangling.
    assert "selected" not in text
    assert "● privacy" in text
    assert "○ generic" in text
    # The profile texts no longer promise security checks the toggle owns.
    assert "security check" not in text
    assert "Security (OWASP)" in text
    assert " on" in text
    assert " off" in text
    # Words, ordinary punctuation and the ● / ○ status dots; no other glyph.
    assert "● on" in text
    assert "○ off" in text
    assert not re.search(r"[^\w\s,.;:()/●○-]", text), text


def test_normalize_choice_drops_stale_values() -> None:
    assert normalize_choice(None) == DEFAULT_STATIC_ANALYSIS_CHOICE
    assert normalize_choice({"profile": "gone", "trackers": "yes", "x": 1}) == (
        DEFAULT_STATIC_ANALYSIS_CHOICE
    )
    assert normalize_choice({"profile": "privacy", "verbose": True})["profile"] == (
        "privacy"
    )


@pytest.fixture
def ui_state_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


def _tui_bus(monkeypatch, answer):
    """Pretend a TUI is running and the dialog returns ``answer``."""
    from sandroid.core import ui_request_bus

    seen = {}

    def fake_request_modal(modal_class, **kwargs):
        seen["modal"] = modal_class
        seen["kwargs"] = kwargs
        return answer

    monkeypatch.setattr(
        ui_request_bus.UIRequestBus, "has_active_handler", lambda self: True
    )
    monkeypatch.setattr(ui_request_bus, "request_modal", fake_request_modal)
    return seen


def test_remembered_choice_is_preselected_and_confirmed_one_saved(
    ui_state_home, monkeypatch
) -> None:
    update_ui_state("static_analysis", {"profile": "privacy", "trackers": False})
    answer = {
        "profile": "privacy",
        "trackers": True,
        "security": False,
        "verbose": False,
    }
    seen = _tui_bus(monkeypatch, answer)
    analyzer = static_analysis.StaticAnalysis(apk_path="/x/app.apk")

    config = analyzer._interactive_configuration()

    assert seen["modal"] is StaticAnalysisModal
    assert seen["kwargs"]["choice"]["profile"] == "privacy"
    assert seen["kwargs"]["choice"]["trackers"] is False
    assert seen["kwargs"]["target"] == "app.apk"
    assert config == {
        "profile": "privacy",
        "run_tracker_analysis": True,
        "run_security_analysis": False,
        "verbose_output": False,
    }
    assert load_ui_state()["static_analysis"] == answer


def test_cancel_remembers_nothing(ui_state_home, monkeypatch) -> None:
    _tui_bus(monkeypatch, None)
    analyzer = static_analysis.StaticAnalysis(apk_path="/x/app.apk")
    assert analyzer._interactive_configuration() is None
    assert "static_analysis" not in load_ui_state()


# -- N6-V6: cancel is no error; a finished run says what it found and where --


def _command_with(monkeypatch, *, ok, state, summary="", error=None):
    import asyncio
    import types

    from sandroid.commands.analysis_commands import StaticAnalysisCommand
    from sandroid.commands.base import CommandContext

    class _Fake:
        def __init__(self, *a, **k):
            self.last_state = state
            self.result_summary = summary
            self.last_results = {"error": error} if error else {}

        def gather(self, interactive=True):
            return ok

        def return_data(self):
            return {}

    monkeypatch.setattr(static_analysis, "StaticAnalysis", _Fake)
    spot = types.SimpleNamespace(get_app_tuple=lambda: ("org.example.app", None))
    ctx = CommandContext(toolbox=object(), spotlight_service=spot)
    return asyncio.run(StaticAnalysisCommand().execute(ctx))


def test_esc_in_the_static_dialog_is_a_cancel_not_an_error(monkeypatch) -> None:
    result = _command_with(monkeypatch, ok=False, state="cancelled")
    assert result.error == "cancelled"
    assert result.message == "Static analysis cancelled"


def test_a_failed_static_run_names_the_error_without_a_dialog(monkeypatch) -> None:
    result = _command_with(monkeypatch, ok=False, state="failed", error="boom")
    assert result.message == "Static analysis failed: boom"
    assert result.data == {"no_dialog": True}


def test_a_finished_static_run_reports_findings_and_path(monkeypatch) -> None:
    summary = "44 security findings (5 high) · results in /r/dexray_insight"
    result = _command_with(monkeypatch, ok=True, state="finished", summary=summary)
    assert result.success
    assert result.message == f"Static analysis completed for org.example.app: {summary}"


def test_summary_line_counts_findings_from_the_security_file(tmp_path) -> None:
    import json

    sec = tmp_path / "dexray_x_security.json"
    sec.write_text(
        json.dumps(
            {
                "findings": [],
                "total_findings": 44,
                "findings_by_severity": {"medium": 28, "low": 11, "high": 5},
            }
        )
    )
    analyzer = static_analysis.StaticAnalysis(apk_path="/x/app.apk")
    line = analyzer._summary_line(str(sec), "/r/dexray_insight")
    assert line == (
        "44 security findings (5 high, 28 medium, 11 low) · "
        "results in /r/dexray_insight"
    )
    analyzer._analysis_config["run_security_analysis"] = False
    assert analyzer._summary_line(None, "/r") == "results in /r"


def test_app_picker_esc_is_a_cancel(monkeypatch) -> None:
    """N6-V6: Esc in the picker logged "WARNING: Command 'C' failed"."""
    import asyncio
    import types

    from sandroid.commands import app_commands
    from sandroid.commands.base import CommandContext

    monkeypatch.setattr(
        app_commands,
        "get_app_selection_service",
        lambda: types.SimpleNamespace(select_app_with_fuzzy_search=lambda: None),
        raising=False,
    )
    cmd = next(
        c()
        for c in vars(app_commands).values()
        if isinstance(c, type) and getattr(c, "key", None) == "C"
    )
    result = asyncio.run(cmd.execute(CommandContext(toolbox=object())))
    assert result.error == "cancelled"
