"""Inspector ←/→ versus a focused widget with its own ←/→.

With the Inspector open, plain ←/→ (priority bindings on ``MainScreen``)
switch its tabs -- except in a text input and in a widget that binds ←/→
itself: the Timeline type bar (``t``) and the chat's agents bar. Textual's
built-in sideways scrolling does not count. No device: the timeline core is
faked (``timeline_fakes``), the chat's agents bar gets its rows directly.
"""

from __future__ import annotations

import time

import pytest
import timeline_fakes
from pilot_helpers import boot, settle, until
from timeline_fakes import make_line

from sandroid.tui.screens.main_screen import handles_left_right
from sandroid.tui.widgets.chat_panel import AgentsBar
from sandroid.tui.widgets.lens_shell import Inspector, InspectorContent
from sandroid.tui.widgets.timeline_lens import TimelineLens, TimelineView, TypeBar

SIZE = (160, 45)
NOW = time.time()
TABS = [("Summary", [("", "1")]), ("Diff", [("", "2")]), ("Events", [("", "3")])]


@pytest.fixture(autouse=True)
def _private_config_home(tmp_path, monkeypatch):
    """Each test gets its own config dir (the UI-state file lives there)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def install_fakes(monkeypatch, tmp_path):
    """``install_fakes(lines)``: see ``timeline_fakes.install``."""

    def _install(lines=None):
        return timeline_fakes.install(monkeypatch, tmp_path, lines)

    return _install


def _app():
    from sandroid.tui.app import SandroidTUI

    return SandroidTUI()


def _lines() -> list[dict]:
    """Two types (files, network) so the type bar has several items."""
    lines = [make_line(i + 1, NOW - 100 + i * 2.5) for i in range(4)]
    lines += [
        make_line(5 + i, NOW - 80 + i * 2.5, "network", "flow", summary="GET /x")
        for i in range(3)
    ]
    return lines


def _agent_row(agent_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "profile": "researcher",
        "title": "check hosts",
        "status": "running",
        "elapsed_s": 12.0,
        "usage": {"prompt_tokens": 9000, "completion_tokens": 200},
    }


async def _timeline_with_inspector(pilot, app):
    """Timeline lens loaded, Inspector open on a three-tab content."""
    ms = await boot(app, pilot)
    await pilot.press("5")
    lens = ms.lens_widget("timeline")
    assert isinstance(lens, TimelineLens)
    await until(pilot, lambda: len(lens.rows) == 7)
    ms.open_inspector(InspectorContent(title="t", tabs=TABS))
    await settle(pilot)
    assert ms.inspector_is_open
    return ms, lens, ms.query_one("#inspector", Inspector)


async def test_type_bar_keeps_left_right_while_the_inspector_is_open(
    install_fakes,
) -> None:
    install_fakes(_lines())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, lens, inspector = await _timeline_with_inspector(pilot, app)
        lens.view.focus()
        await settle(pilot)
        await pilot.press("t")
        bar = lens.query_one("#tl-types", TypeBar)
        await until(pilot, lambda: bar.has_focus)
        assert len(bar.items) >= 2
        tab = inspector.tab_index
        start = bar.index
        await pilot.press("right")
        await until(pilot, lambda: bar.index == (start + 1) % len(bar.items))
        assert inspector.tab_index == tab
        await pilot.press("left")
        await until(pilot, lambda: bar.index == start)
        assert inspector.tab_index == tab
        # [ / ] still switch the tabs there.
        await pilot.press("right_square_bracket")
        await until(pilot, lambda: inspector.tab_index == (tab + 1) % 3)
        assert bar.index == start


async def test_agents_bar_keeps_left_right_while_the_inspector_is_open(
    install_fakes,
) -> None:
    install_fakes(_lines())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, _lens, inspector = await _timeline_with_inspector(pilot, app)
        await pilot.press("ctrl+y")
        await until(pilot, lambda: ms.chat_has_focus)
        panel = ms.query_one("#chat-panel")
        bar = panel.query_one(AgentsBar)
        rows = [_agent_row("a-re-111111"), _agent_row("a-re-222222")]
        # The panel refreshes the bar from its agent manager now and then
        # (no session here: no rows); keep the two rows across refreshes.
        panel._agent_rows = lambda: list(rows)
        panel._refresh_agents()
        await until(pilot, lambda: bar.display and len(bar.rows) == 2)
        bar.focus()
        await until(pilot, lambda: bar.has_focus)
        assert ms.inspector_is_open
        tab = inspector.tab_index
        assert bar.selected == 0
        await pilot.press("right")
        await until(pilot, lambda: bar.selected == 1)
        assert inspector.tab_index == tab
        await pilot.press("left")
        await until(pilot, lambda: bar.selected == 0)
        assert inspector.tab_index == tab


async def test_left_right_switch_tabs_when_the_focus_has_no_own_arrows(
    install_fakes,
) -> None:
    install_fakes(_lines())
    app = _app()
    async with app.run_test(size=SIZE) as pilot:
        ms, lens, inspector = await _timeline_with_inspector(pilot, app)
        # The timeline list binds only up / down.
        lens.view.focus()
        await until(pilot, lambda: isinstance(app.focused, TimelineView))
        assert not handles_left_right(app.focused, stop=inspector)
        start = inspector.tab_index
        await pilot.press("right")
        await until(pilot, lambda: inspector.tab_index == (start + 1) % 3)
        await pilot.press("left")
        await until(pilot, lambda: inspector.tab_index == start)
        # The Inspector's own scroll area: Textual's scroll_left / right do
        # not count, so ←/→ still switch the tabs.
        scroll = inspector.query_one("#inspector-scroll")
        scroll.focus()
        await until(pilot, lambda: app.focused is scroll)
        assert not handles_left_right(scroll, stop=inspector)
        await pilot.press("right")
        await until(pilot, lambda: inspector.tab_index == (start + 1) % 3)


def test_handles_left_right_counts_own_bindings_only() -> None:
    """Own ←/→ actions count; Textual's scroll / cursor actions do not."""
    from textual.containers import VerticalScroll
    from textual.widgets import DataTable

    assert handles_left_right(TypeBar())
    assert handles_left_right(AgentsBar())
    assert not handles_left_right(DataTable())
    assert not handles_left_right(VerticalScroll())
    assert not handles_left_right(None)
