"""Shared helper for applying Textual's compact widget mode.

Provides a single sweep that sets ``compact=True`` on every Input/Select/
RadioSet under a given node, so modals and screens don't have to hand-roll
CSS overrides for stock widget sizing.
"""

from textual.dom import DOMNode


def apply_compact_widgets(node: DOMNode) -> None:
    """Set ``compact=True`` on every Input/Select/RadioSet under *node*.

    Widgets carrying the ``no-compact`` class are skipped -- used for
    widgets that rely on their own meaningful border-color states (e.g.
    focus/error indicators) which compact mode's borderless rendering
    would otherwise silently hide.

    Args:
        node: The DOM node (screen, modal, etc.) to sweep for widgets.
    """
    for widget in node.query("Input, Select, RadioSet").exclude(".no-compact"):
        widget.compact = True
