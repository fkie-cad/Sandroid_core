"""Case-aware, human-readable key labels for the TUI.

Textual key strings are case-sensitive: ``"r"`` and ``"R"`` (= Shift+R) are
different bindings. Rendering both as ``R`` (the old behaviour of the footer,
the ``?`` catalog and the command palette) made e.g. Spotlight's ``R`` Restart
look identical to the global ``r`` Record. Every place that shows a key to the
user goes through :func:`format_key` so a shifted letter is always marked:

* ``compact`` (footer, in-panel hint lines): ``r`` -> ``r``, ``R`` ->
  ``Shift+R``, ``ctrl+b`` -> ``^b``, ``shift+right`` -> ``Shift+Right``.
* ``long`` (help catalog, palette, detail panes): ``r`` -> ``r``,
  ``R`` -> ``Shift+R``, ``ctrl+b`` -> ``Ctrl+B``, ``question_mark`` -> ``?``.

Keys are words, never glyphs (the user's no-glyph rule covers key names):
arrows read ``Left`` / ``Right`` / ``Up`` / ``Down``, Enter ``Enter``, Shift
``Shift+``. :func:`key_words` turns glyphs in hand-written labels (a
binding's ``key_display``, help rows) into the same words.
"""

from __future__ import annotations

#: The Shift prefix in both styles (a word, not the old ``⇧`` glyph).
SHIFT_PREFIX = "Shift+"

#: Key glyphs -> their words. The one mapping for every key label: help,
#: the footer and the command palette all go through it.
KEY_WORDS: dict[str, str] = {
    "←": "Left",
    "→": "Right",
    "↑": "Up",
    "↓": "Down",
    "⏎": "Enter",
    "↵": "Enter",
    "⇧": "Shift+",
    "⌥": "Alt+",
    "⌫": "Backspace",
    "⇥": "Tab",
}


def key_words(text: str) -> str:
    """*text* with key glyphs replaced by their words (``⇧←`` -> ``Shift+Left``)."""
    for glyph, word in KEY_WORDS.items():
        text = text.replace(glyph, word)
    return text.replace("Shift++", "Shift+").replace("Alt++", "Alt+")

#: Named keys -> (compact, long) display.
_NAMED: dict[str, tuple[str, str]] = {
    "space": ("Space", "Space"),
    " ": ("Space", "Space"),
    "enter": ("Enter", "Enter"),
    "escape": ("esc", "Esc"),
    "tab": ("Tab", "Tab"),
    "backspace": ("Backspace", "Backspace"),
    "delete": ("del", "Del"),
    "question_mark": ("?", "?"),
    "comma": (",", ","),
    "full_stop": (".", "."),
    "slash": ("/", "/"),
    "left_square_bracket": ("[", "["),
    "grave_accent": ("`", "`"),
    "equals_sign": ("=", "="),
    "minus": ("-", "-"),
    "plus": ("+", "+"),
    "number_sign": ("#", "#"),
    "asterisk": ("*", "*"),
    "less_than_sign": ("<", "<"),
    "greater_than_sign": (">", ">"),
    "right_square_bracket": ("]", "]"),
    "left_curly_bracket": ("{", "{"),
    "right_curly_bracket": ("}", "}"),
    "up": ("Up", "Up"),
    "down": ("Down", "Down"),
    "left": ("Left", "Left"),
    "right": ("Right", "Right"),
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
            prefix += "Alt+"
        if "shift" in mods:
            prefix += SHIFT_PREFIX
        return prefix + label

    order = [m for m in ("ctrl", "alt", "shift") if m in mods]
    order += [m for m in mods if m not in ("ctrl", "alt", "shift")]
    return "+".join([m.title() for m in order] + [label])
