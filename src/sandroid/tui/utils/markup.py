r"""Put untrusted text (device files, diffs, flow bodies, SMS, paths, AI text)
into Textual widgets without it being read as markup.

``rich.markup.escape`` (and Textual's own ``textual.markup.escape``, the same
regex) only escapes ``[`` followed by ``a-z # / @``. Textual 8's markup
parser also treats ``["``, ``[A-Z...=`` and similar as tags, so a cookie value
such as ``{"meta.wikimedia.org":["WMF-Uniq=...`` raises ``MarkupError`` and
takes the whole app down.

- :func:`plain` gives a :class:`~textual.content.Content` that is never
  parsed: use it when the whole widget text is untrusted.
- :func:`escape` escapes every ``[`` for Textual markup (``Static``,
  ``Label``, ``notify``, ``Content.from_markup``): use it when untrusted text
  is mixed into a markup string. Not for Rich parsers (``RichLog.write`` of a
  str, ``DataTable`` str cells, ``Text.from_markup``): Rich eats a
  data backslash before ``[`` (``a\[b]``); keep ``rich.markup.escape`` there.
"""

from __future__ import annotations

from typing import Any

from textual.content import Content


def escape(text: Any) -> str:
    r"""Escape ``text`` so Textual's markup parser shows it literally.

    A trailing backslash would escape the next tag (``x\[/b]``); Textual
    has no escape for a backslash, so a zero-width space ends the text.
    """
    out = str(text).replace("[", "\\[")
    return out + "\u200b" if out.endswith("\\") else out


def plain(text: Any) -> Content:
    """``text`` as Content that is never parsed as markup."""
    return Content(str(text))


__all__ = ["escape", "plain"]
