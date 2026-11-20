"""The ``?`` help lists every key: lens extras, chat dock, log drawer, Devices.

Rows come from the real BINDINGS where they say enough; hand-written rows
and longer wording are checked against the bindings they describe, so the
help cannot list a key that does nothing.
"""

from __future__ import annotations

import importlib

import pytest
from pilot_helpers import boot, settle, until

from sandroid.tui.screens import help_screen as hs


def _binding_keys(cls) -> set[str]:
    """Every key bound on ``cls`` or a base class (Binding or tuple)."""
    keys: set[str] = set()
    for klass in cls.__mro__:
        for entry in klass.__dict__.get("BINDINGS", []):
            key = entry.key if hasattr(entry, "key") else entry[0]
            keys.update(k.strip() for k in key.split(","))
    return keys


def _section_raw_keys(heading: str) -> set[str]:
    keys: set[str] = set()
    for title, module, cls_name in hs._PANEL_SECTIONS:
        if title == heading:
            for _shown, _desc, raw in hs._panel_binding_rows(module, cls_name):
                keys.update(raw)
    return keys


# --------------------------------------------------------------------------
# RESERVED
# --------------------------------------------------------------------------

NEW_RESERVED = {
    "0",
    "L",
    "left_square_bracket",
    "right_square_bracket",
    "left_curly_bracket",
    "right_curly_bracket",
    "asterisk",
    "left",
    "right",
    "shift+left",
    "shift+right",
    "shift+up",
    "shift+down",
}


def test_reserved_holds_the_main_screen_wide_keys() -> None:
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.screens.main_screen import MainScreen

    assert NEW_RESERVED <= hs.RESERVED
    # Each one really is bound app-wide or on the main screen ...
    bound = _binding_keys(SandroidTUI) | _binding_keys(MainScreen)
    assert bound >= NEW_RESERVED
    # ... and no rebindable action uses it by default.
    defaults = {b.key for b in SandroidTUI.BINDINGS if b.id}
    assert not hs.RESERVED & defaults


# --------------------------------------------------------------------------
# rows are checked against the bindings they describe
# --------------------------------------------------------------------------


def test_row_text_only_rewords_real_bindings() -> None:
    # Main-screen bindings with the Inspector prefix are listed (and
    # reworded) under "Inspector (while open)".
    moved = {
        k
        for _s, d, raw in hs._panel_binding_rows(
            "sandroid.tui.screens.main_screen", "MainScreen"
        )
        if d.startswith(hs._INSPECTOR_PREFIX)
        for k in raw
    }
    for (heading, key), _text in hs._ROW_TEXT.items():
        keys = _section_raw_keys(heading)
        if heading == "Inspector (while open)":
            keys |= moved
        assert key in keys, (heading, key)


def test_hand_written_sections_cover_the_real_keys() -> None:
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.activity_log import ActivityLog
    from sandroid.tui.widgets.tool_permission_prompt import ToolPermissionPrompt

    approval = {
        k for _s, _d, raw in hs._HAND_SECTIONS["AI chat › approval prompt"] for k in raw
    }
    assert approval == _binding_keys(ToolPermissionPrompt)

    log_keys = {k for _s, _d, raw in hs._HAND_SECTIONS["Log drawer"] for k in raw}
    app_actions = {b.key: b.action for b in SandroidTUI.BINDINGS}
    assert app_actions["grave_accent"] == "toggle_log"
    assert app_actions["Y"] == "copy_log"
    # The vim-style keys are App bindings that scroll the log (_scroll_log).
    app_scroll = {k for k, a in app_actions.items() if a.startswith("scroll_")}
    assert {"j", "ctrl+j", "ctrl+k", "ctrl+d", "ctrl+u"} <= app_scroll
    assert log_keys - {"grave_accent", "Y"} <= _binding_keys(ActivityLog) | app_scroll


def test_extra_rows_name_real_keys() -> None:
    from sandroid.tui.screens.devices_screen import _HubTable

    assert "enter" in _binding_keys(_HubTable)
    for heading in ("Timeline lens › t type bar", "AI chat", "Devices screen (D)"):
        assert _section_raw_keys(heading), heading


def test_slash_commands_come_from_the_chat() -> None:
    chat = importlib.import_module("sandroid.tui.widgets.chat_panel")
    rows = hs._slash_rows()
    assert [r[0] for r in rows] == list(chat.SLASH_HELP)


# --------------------------------------------------------------------------
# rendered help, from every lens
# --------------------------------------------------------------------------

#: heading -> keys (as shown in the key column) that must be listed there.
EXPECTED: dict[str, tuple[str, ...]] = {
    "Timeline lens": ("[/]", "[t]", "[Esc]"),
    "Timeline lens › t type bar": ("[Left]", "[Right]", "[Space / Enter]", "[Esc]"),
    "Files lens": ("[Shift+H]", "[Shift+X]"),
    "Network lens": ("[Shift+H]", "[Shift+X]", "[!]"),
    "AI chat": (
        "[Ctrl+X]",
        "[Ctrl+L]",
        "[Enter]",
        "[Esc]",
        "[Shift+Up]",
        "[Shift+Down]",
        "[PgUp]",
        "[PgDn]",
    ),
    "AI chat › approval prompt": ("[1]", "[2]", "[3]", "[Esc]"),
    "AI chat › agents bar": ("[Left]", "[Right]", "[Enter]"),
    "AI chat › slash commands": ("[/new]", "[/threads]", "[/compact]"),
    "Log drawer": ("[`]", "[Shift+Y]", "[Home / End]"),
    "Devices screen (D)": (
        "[Enter]",
        "[c]",
        "[n]",
        "[h]",
        "[s]",
        "[w]",
        "[e]",
        "[x]",
        "[Shift+R]",
        "[a]",
        "[Ctrl+R]",
        "[j]",
        "[k]",
        "[Esc]",
    ),
}


def _sections(rows: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = None
    for row in rows:
        if row.startswith("──"):
            current = row.strip("─ ")
            out.setdefault(current, [])
        elif current is not None:
            out[current].append(row.rstrip())
    return out


@pytest.mark.parametrize("size", [(200, 50)])
async def test_help_lists_the_previously_missing_rows_from_every_lens(size) -> None:
    from rich.text import Text
    from textual.widgets import OptionList

    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.lens_shell import LENSES

    app = SandroidTUI()
    async with app.run_test(size=size) as pilot:
        await boot(app, pilot)
        for spec in LENSES:
            await pilot.press(spec.key)
            await settle(pilot)
            await pilot.press("question_mark")
            await settle(pilot)
            screen = app.screen
            assert type(screen).__name__ == "HelpScreen"
            options = screen.query_one("#kb-list", OptionList)
            rows = [
                Text.from_markup(str(options.get_option_at_index(i).prompt)).plain
                for i in range(options.option_count)
            ]
            sections = _sections(rows)
            for heading, keys in EXPECTED.items():
                assert heading in sections, (spec.id, heading)
                listed = sections[heading]
                for key in keys:
                    assert any(r.endswith(key) for r in listed), (spec.id, heading, key)
            # The chat size keys moved from "Main screen" to the chat.
            assert not any("chat" in r.lower() for r in sections["Main screen"])
            general = "\n".join(sections["General"])
            assert "[Ctrl+P]" in general
            assert "SSL unpinning on/off" in general
            # Spotlight globals (app.py c / C) are in the global section.
            spot = sections["Spotlight"]
            assert any(
                r.startswith("Use foreground app") and r.endswith("[c]") for r in spot
            )
            assert any(
                r.startswith("Pick an app") and r.endswith("[Shift+C]") for r in spot
            )
            # Wider wording for terse labels.
            assert any(
                r.startswith("Stop the turn and its agents")
                for r in sections["AI chat"]
            )
            assert any(r.startswith("Back to live") for r in sections["Main screen"])
            width = options.scrollable_content_region.width
            assert max(len(r) for r in rows) <= width
            await pilot.press("escape")
            await settle(pilot)


async def test_log_scroll_keys_reach_the_log_on_the_main_screen() -> None:
    """The vim-style keys scroll the log drawer (the App looked the log
    up on its default screen and the keys silently did nothing).
    """
    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets import ActivityLog

    app = SandroidTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await boot(app, pilot)
        ms = app.screen
        log = ms.query_one("#activity-log", ActivityLog)
        ms.toggle_log_drawer()
        await settle(pilot)
        for i in range(200):
            log.log_info(f"line {i}")
        await until(pilot, lambda: log.max_scroll_y > 20)
        app.action_scroll_bottom()
        await until(pilot, lambda: log.scroll_y > 10)
        app.action_scroll_top()
        await until(pilot, lambda: log.scroll_y < 1)
        app.action_scroll_half_down()
        await until(pilot, lambda: log.scroll_y > 5)


def test_hand_written_rows_fit_at_100_columns() -> None:
    """At 100 columns a description-only row has 32 + 2 + 36 cells: the
    Timeline rows were cut with "…" at 170 and 100 columns.
    """
    field = hs._NAME_W + 2 + 36
    texts = [d for rows in hs._LENS_EXTRA_ROWS.values() for _k, d, _r in rows]
    texts += list(hs._ROW_TEXT.values())
    too_long = [t for t in texts if len(t) > field]
    assert too_long == []
    timeline = [d for _k, d, _r in hs._LENS_EXTRA_ROWS["Timeline lens"]]
    assert any(t.startswith("Inspect the line") for t in timeline)
    assert any(t.startswith("Close / or the type bar") for t in timeline)


@pytest.mark.parametrize("size", [(170, 50), (100, 40)])
async def test_timeline_help_rows_are_not_cut(size) -> None:
    from rich.text import Text
    from textual.widgets import OptionList

    from sandroid.tui.app import SandroidTUI
    from sandroid.tui.widgets.lens_shell import LENSES

    spec = next(s for s in LENSES if s.id == "timeline")
    app = SandroidTUI()
    async with app.run_test(size=size) as pilot:
        await boot(app, pilot)
        await pilot.press(spec.key)
        await settle(pilot)
        await pilot.press("question_mark")
        await until(pilot, lambda: type(app.screen).__name__ == "HelpScreen")
        await settle(pilot)
        options = app.screen.query_one("#kb-list", OptionList)
        rows = [
            Text.from_markup(str(options.get_option_at_index(i).prompt)).plain
            for i in range(options.option_count)
        ]
        for head in ("Inspect the line", "Close / or the type bar", "Filter: text"):
            row = next(r for r in rows if r.startswith(head))
            assert "…" not in row, row


def test_proxy_settings_rows_come_from_the_dialog() -> None:
    """sandroid-proxy's dialog keys (BINDINGS with descriptions) are listed."""
    keys = _section_raw_keys("Proxy settings (y)")
    for key in ("a", "f", "p", "i", "r", "shift+left", "shift+right"):
        assert any(key in k.split(",") for k in keys), key


def test_help_key_names_are_words_not_glyphs() -> None:
    """The no-glyph rule covers key names: help writes Shift+Left, Enter, Up."""
    assert hs._format_key_display("shift+left") == "Shift+Left"
    assert hs._format_key_display("enter") == "Enter"
    assert hs.key_words("⇧Tab / ⏎ / ↑↓") == "Shift+Tab / Enter / UpDown"
    rows = []
    for _t, module, cls_name in hs._PANEL_SECTIONS:
        rows += [shown for shown, _d, _r in hs._panel_binding_rows(module, cls_name)]
    for section in hs._HAND_SECTIONS.values():
        rows += [shown for shown, _d, _r in section]
    glyphs = set("←→↑↓⏎↵⇧⌫⇥")
    assert not [r for r in rows if glyphs & set(r)]


def test_static_analysis_rows_come_from_the_dialog() -> None:
    """insight-privacy's `a` dialog keys are listed from its BINDINGS."""
    keys = _section_raw_keys("Static analysis (a)")
    assert {"enter", "p", "t", "s", "v"} <= keys
