"""Case-aware, human-readable key labels for the TUI.

Textual key strings are case-sensitive: ``"r"`` and ``"R"`` (= Shift+R) are
different bindings. Rendering both as ``R`` (the old behaviour of the footer,
the ``?`` catalog and the command palette) made e.g. Spotlight's ``R`` Restart
look identical to the global ``r`` Record. Every place that shows a key to the
user goes through :func:`format_key` so a shifted letter is always marked:

* ``compact`` (footer, in-panel hint lines): ``r`` -> ``r``, ``R`` -> ``⇧R``,
  ``ctrl+b`` -> ``^b``, ``shift+right`` -> ``⇧→``.
* ``long`` (help catalog, palette, detail panes): ``r`` -> ``r``,
  ``R`` -> ``Shift+R``, ``ctrl+b`` -> ``Ctrl+B``, ``question_mark`` -> ``?``.
"""

from __future__ import annotations

SHIFT_GLYPH = "⇧"

#: Named keys -> (compact, long) display.
_NAMED: dict[str, tuple[str, str]] = {
    "space": ("Space", "Space"),
    " ": ("Space", "Space"),
    "enter": ("⏎", "Enter"),
    "escape": ("esc", "Esc"),
    "tab": ("⇥", "Tab"),
    "backspace": ("⌫", "Backspace"),
    "delete": ("del", "Del"),
    "question_mark": ("?", "?"),
    "comma": (",", ","),
    "full_stop": (".", "."),
    "slash": ("/", "/"),
    "left_square_bracket": ("[", "["),
    "right_square_bracket": ("]", "]"),
    "up": ("↑", "↑"),
    "down": ("↓", "↓"),
    "left": ("←", "←"),
    "right": ("→", "→"),
    "home": ("home", "Home"),
    "end": ("end", "End"),
    "pageup": ("pgup", "PgUp"),
    "pagedown": ("pgdn", "PgDn"),
}


def _is_shifted_letter(part: str) -> bool:
    return len(part) == 1 and part.isalpha() and part.isupper()


def format_key(key: str | None, style: str = "long") -> str:
    """Format a Textual key string for display, keeping Shift visible.

    Args:
        key: Raw key (``"r"``, ``"R"``, ``"ctrl+b"``, ``"shift+right"``, ...).
            Comma-separated alternatives (``"q,escape"``) use the first one.
        style: ``"compact"`` (footer/hint lines) or ``"long"`` (help/palette).

    Returns:
        The display label, ``"—"`` for an empty key.
    """
    if key is None or key == "":
        return "—"
    if key == " ":
        return "Space"
    key = key.split(",")[0].strip() or key
    compact = style == "compact"

    *mods, base = key.split("+") if key != "+" else ["+"]
    mods = [m.lower() for m in mods if m]

    # A bare uppercase letter *is* Shift+letter in Textual.
    if _is_shifted_letter(base) and "shift" not in mods:
        mods.append("shift")

    if base.lower() in _NAMED:
        label = _NAMED[base.lower()][0 if compact else 1]
    elif len(base) == 1:
        # Keep the real case for plain letters; shifted ones are upper-case.
        label = base.upper() if ("shift" in mods or (mods and not compact)) else base
    else:
        label = base if compact else base.title()

    if compact:
        prefix = ""
        if "ctrl" in mods:
            prefix += "^"
        if "alt" in mods:
            prefix += "⌥"
        if "shift" in mods:
            prefix += SHIFT_GLYPH
        return prefix + label

    order = [m for m in ("ctrl", "alt", "shift") if m in mods]
    order += [m for m in mods if m not in ("ctrl", "alt", "shift")]
    return "+".join([m.title() for m in order] + [label])
