"""Shared box-rendering utilities for Rich console output.

Provides functions for stripping ANSI/Rich markup and creating properly
aligned box lines with Unicode borders. Used across analysis modules and
services that render interactive configuration menus.

Example usage::

    from sandroid.tui.utils.box_renderer import box_line, strip_color_codes

    # Full-width box line with configurable border
    print(box_line("[bold]Title[/bold]", width=76, align="center"))

    # Get the visual length of marked-up text
    visual = strip_color_codes("[success]OK[/success]")  # -> "OK"
"""

import re

# ---------------------------------------------------------------------------
# Compiled regexes (module-level to avoid recompilation on every call)
# ---------------------------------------------------------------------------

_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_RICH_MARKUP_RE = re.compile(r"\[/?[a-zA-Z0-9_./#\s]+\]")

# Placeholder used to protect escaped brackets during stripping
_ESCAPED_BRACKET_PLACEHOLDER = "\x00ESCAPED_BRACKET\x00"


def strip_color_codes(text: str) -> str:
    r"""Strip ANSI color codes and Rich markup to get the visual text.

    Handles both ANSI escape sequences and Rich console markup tags
    (e.g. ``[bold]``, ``[success]``, ``[/error]``).  Escaped brackets
    (``\[``) are preserved as literal ``[`` characters.

    Args:
        text: Text possibly containing ANSI color codes and Rich markup.

    Returns:
        Text with color codes and markup removed.
    """
    # Strip ANSI escape codes
    text = _ANSI_ESCAPE_RE.sub("", text)

    # Protect escaped brackets, strip Rich tags, then restore
    text = text.replace("\\[", _ESCAPED_BRACKET_PLACEHOLDER)
    text = _RICH_MARKUP_RE.sub("", text)
    text = text.replace(_ESCAPED_BRACKET_PLACEHOLDER, "[")

    return text


def box_line(
    content: str,
    width: int = 76,
    align: str = "center",
    border_style: str = "primary",
) -> str:
    """Create a properly aligned box line with Rich-markup-aware padding.

    The line is bounded by ``║`` characters styled with *border_style*.
    Content may contain Rich markup; the visual (displayed) length is used
    for padding calculations.

    Args:
        content: Text content (may contain Rich markup).
        width: Total width of the inner content area (default 76).
        align: Alignment — ``"center"``, ``"left"``, or ``"right"``.
        border_style: Rich style name applied to the ``║`` borders
            (default ``"primary"``).

    Returns:
        Formatted box line string with styled borders and padding.
    """
    visual_length = len(strip_color_codes(content))

    if align == "center":
        total_padding = width - visual_length
        left_pad = total_padding // 2
        right_pad = total_padding - left_pad
    elif align == "left":
        left_pad = 2
        right_pad = width - visual_length - left_pad
    else:  # right
        right_pad = 2
        left_pad = width - visual_length - right_pad

    return (
        f"[{border_style}]\u2551[/{border_style}]"
        f"{' ' * left_pad}{content}{' ' * right_pad}"
        f"[{border_style}]\u2551[/{border_style}]"
    )


def make_box_line(width: int, border_style: str = "primary"):
    """Return a *box_line* helper pre-configured for a fixed width.

    This is a convenience factory for call sites that define a local
    ``BOX_WIDTH`` and want a short helper without passing *width* every
    time.  The returned callable has the same signature as :func:`box_line`
    minus the *width* parameter.

    Args:
        width: Inner content area width baked into the returned helper.
        border_style: Default border style for the returned helper.

    Returns:
        A callable ``(content, align="center") -> str`` that delegates to
        :func:`box_line`.

    Example::

        _box_line = make_box_line(60)
        _box_line("[bold]Title[/bold]")
        _box_line("Left text", align="left")
    """

    def _box_line(content: str, align: str = "center") -> str:
        return box_line(content, width=width, align=align, border_style=border_style)

    return _box_line


__all__ = [
    "box_line",
    "make_box_line",
    "strip_color_codes",
]
