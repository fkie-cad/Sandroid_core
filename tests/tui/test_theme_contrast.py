"""WCAG contrast floors of every theme's text tokens.

Light themes: every text token >= 4.5:1 (dim / muted >= 3:1) on every lens
and chrome surface and on the row tints that carry text; the Textual base
colours (``$warning`` / ``$success`` / ``$error`` / ``$accent`` text in the
modals) too. Dark themes: the lens text tokens on their background.
"""

from __future__ import annotations

import pytest

from sandroid.tui.themes import THEMES, build_textual_theme

#: Lens tokens drawn as text (>= 4.5:1).
LENS_TEXT = (
    "text", "label", "title", "accent", "ok", "warn", "bad", "user", "typed",
    "screen", "shot", "highlight_1", "highlight_2", "highlight_3", "highlight_4",
)  # fmt: skip
#: Quiet lens text tiers (>= 3:1).
LENS_QUIET = ("dim", "muted", "header")
#: ``Theme`` fields drawn as text (the .tcss rules, the chat, the status strip).
THEME_TEXT = (
    "text", "primary", "secondary", "accent", "warning", "success", "error",
    "tool_color", "assistant_reply_color", "waiting_color", "key_color",
)  # fmt: skip
THEME_QUIET = ("text_muted", "muted_status_color")
#: Row tints that carry text: (token, blend amount). The Timeline's user /
#: typed rows and privacy rows (13 %), the AI highlight sets (18 %), the
#: row-annotation tints (13 %), a changed watched file's row in the Files
#: lens (``files_panel.WATCHED_TINT``).
TINTS = (
    ("user", 0.13), ("typed", 0.13), ("warn", 0.13), ("accent", 0.13),
    ("highlight_1", 0.18), ("highlight_2", 0.18), ("highlight_3", 0.18),
    ("highlight_4", 0.18), ("title", 0.08), ("ok", 0.13), ("bad", 0.13),
)  # fmt: skip
#: Tokens drawn on those tints too: the Files ops letters (C M R D A).
ON_TINTS = ("ok", "screen", "warn", "bad", "title")

LIGHT = sorted(name for name, theme in THEMES.items() if not theme.is_dark)
DARK = sorted(name for name, theme in THEMES.items() if theme.is_dark)


def _lum(hexv: str) -> float:
    text = hexv.lstrip("#")
    rgb = [int(text[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def blend(base: str, colour: str, amount: float) -> str:
    a, b = base.lstrip("#"), colour.lstrip("#")
    return "#" + "".join(
        f"{round(int(a[i : i + 2], 16) * (1 - amount) + int(b[i : i + 2], 16) * amount):02X}"
        for i in (0, 2, 4)
    )


def _check(failures: list[str], what: str, fg: str, bg: str, floor: float) -> None:
    got = ratio(fg, bg)
    if got < floor:
        failures.append(f"{what}: {fg} on {bg} = {got:.2f} < {floor}")


def test_there_are_light_and_dark_themes() -> None:
    assert {"light", "paper", "daylight"} <= set(LIGHT)
    assert "default" in DARK


@pytest.mark.parametrize("name", LIGHT)
def test_light_theme_text_tokens_are_readable_everywhere(name: str) -> None:
    theme = THEMES[name]
    p = theme.lens
    surfaces = {
        "bg": p.bg, "panel": p.panel, "cursor": p.cursor, "band": p.band,
        "stripe": p.stripe, "background": theme.background,
        "surface": theme.surface,
    }  # fmt: skip
    failures: list[str] = []
    for where, bg in surfaces.items():
        for token in LENS_TEXT:
            _check(failures, f"lens.{token} on {where}", getattr(p, token), bg, 4.5)
        for token in LENS_QUIET:
            _check(failures, f"lens.{token} on {where}", getattr(p, token), bg, 3)
        for field in THEME_TEXT:
            _check(failures, f"{field} on {where}", getattr(theme, field), bg, 4.5)
        for field in THEME_QUIET:
            _check(failures, f"{field} on {where}", getattr(theme, field), bg, 3)
        for status, colour in theme.status_colors.items():
            _check(failures, f"status {status} on {where}", colour, bg, 4.5)
    for token, amount in TINTS:
        colour = getattr(p, token)
        tint = blend(p.bg, colour, amount)
        _check(failures, f"lens.{token} on its tint", colour, tint, 4.5)
        _check(failures, f"lens.text on the {token} tint", p.text, tint, 4.5)
        for quiet in LENS_QUIET:
            what = f"lens.{quiet} on the {token} tint"
            _check(failures, what, getattr(p, quiet), tint, 3)
        for other in ON_TINTS:
            what = f"lens.{other} on the {token} tint"
            _check(failures, what, getattr(p, other), tint, 4.5)
    # The focused cursor / header chip (Timeline cursor row, Inspector lists):
    # the floor the user / screen tokens already meet under the cursor.
    for surface in ("cursor_focus", "band_focus"):
        for token in LENS_TEXT:
            what = f"lens.{token} on {surface}"
            _check(failures, what, getattr(p, token), getattr(p, surface), 3)
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("name", LIGHT)
def test_light_theme_textual_base_colours_are_readable(name: str) -> None:
    """``[$warning]...`` / ``color: $success`` in the modals: not
    textual-light's amber / light green (~2:1 on white).
    """
    theme = THEMES[name]
    textual = build_textual_theme(theme)
    failures: list[str] = []
    for field in ("accent", "warning", "success", "error"):
        for bg in (theme.lens.bg, theme.background, theme.surface):
            _check(failures, f"${field}", getattr(textual, field), bg, 4.5)
    assert not failures, "\n".join(failures)


@pytest.mark.parametrize("name", DARK)
def test_dark_theme_text_tokens_are_readable_on_their_background(name: str) -> None:
    p = THEMES[name].lens
    failures: list[str] = []
    for token in LENS_TEXT:
        _check(failures, f"lens.{token}", getattr(p, token), p.bg, 4.5)
    for token in LENS_QUIET:
        _check(failures, f"lens.{token}", getattr(p, token), p.bg, 3)
    assert not failures, "\n".join(failures)


def test_the_watched_row_tint_is_one_the_contrast_test_covers() -> None:
    from sandroid.tui.widgets.files_panel import WATCHED_TINT

    assert WATCHED_TINT in TINTS


def test_the_files_op_letters_use_checked_text_tokens() -> None:
    """The ops column (C M R D A o) is drawn in lens tokens this test checks."""
    from sandroid.tui.widgets.monitor_view import OP_TOKENS, OPS, op_color

    assert set(OP_TOKENS) == set(OPS)
    assert set(OP_TOKENS.values()) <= set(LENS_TEXT) | set(LENS_QUIET)
    assert op_color("create") == THEMES["default"].lens.ok  # outside an app
    assert op_color("unknown") is None
