#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Base modal for the Sandroid friTap capture wizard.

Ported from ``friTap/tui/modals/base.py`` (``FriTapModal``) and re-themed with
Sandroid's color scheme. Provides ESC to dismiss, auto-focus of the first
focusable widget, and Enter-from-Input to press the primary button.

The standalone friTap wizard styles its modals with friTap-specific Textual
theme variables (``$fritap-bg-modal`` etc.) and an inline ``c(role)`` color
helper backed by friTap's registered ``Theme``. Sandroid does not register
those variables, so this base:

* uses Sandroid's own Textual theme variables (``$surface``, ``$primary``,
  ``$text-muted`` …) for structural CSS so the wizard adapts to the active
  Sandroid theme, and
* provides a local :func:`c` helper returning Sandroid's default
  "Midnight Cyan" palette hexes for the inline Rich markup the ported modals
  use (titles, key hints) — matching the hexes already hardcoded by
  ``FriTapPanel`` / ``styles.tcss``.

Each ported wizard modal therefore only differs from its friTap original by its
imports (``from .base import FriTapWizardModal, c``) and the base class name.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Button, Input

T = TypeVar("T")


# Sandroid "Midnight Cyan" palette (see tui/styles.tcss + tui/widgets/fritap_panel.py).
# Used for inline Rich markup colors where a CSS class cannot be applied.
_SANDROID_COLORS: dict[str, str] = {
    "primary": "#38bdf8",
    "secondary": "#818cf8",
    "accent": "#22d3ee",
    "success": "#4ade80",
    "warning": "#facc15",
    "warning-amber": "#f59e0b",
    "error": "#fb7185",
    "info": "#7dd3fc",
    "foreground": "#cbd5f5",
    "text-secondary": "#94a3b8",
    "text-muted": "#64748b",
    "text-dim": "#8f9bb3",
    "text-disabled": "#6b7280",
}


def c(role: str) -> str:
    """Return the Sandroid palette color for *role* for inline Rich markup.

    Mirrors the signature of friTap's ``tui.themes.c`` so ported modals can keep
    their ``c('primary')`` / ``c('text-muted')`` calls verbatim.
    """
    return _SANDROID_COLORS.get(role, "#ffffff")


class FriTapWizardModal(ModalScreen[T], Generic[T]):
    """Base modal screen with standard dismiss/focus behavior (Sandroid-themed)."""

    DEFAULT_CSS = """
    FriTapWizardModal {
        align: center middle;
        background: $background 85%;
    }

    FriTapWizardModal > #modal-container {
        width: 70;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
    }

    FriTapWizardModal .modal-title {
        text-align: center;
        text-style: bold;
        color: $primary;
        margin-bottom: 0;
    }

    /* Compact, 1-row buttons (mirrors SandroidModal's button-row treatment so
       Textual's default tall borders don't inflate the modal height). */
    FriTapWizardModal .button-row {
        height: 1;
        align: center middle;
        margin-top: 1;
    }

    FriTapWizardModal .button-row Button {
        height: 1;
        min-height: 1;
        min-width: 14;
        padding: 0 1;
        margin: 0 1;
        border: none;
        content-align: center top;
        text-align: center;
    }

    FriTapWizardModal .button-row Button.-style-default.-primary,
    FriTapWizardModal .button-row Button.-style-default.-primary:hover,
    FriTapWizardModal .button-row Button.-style-default.-primary:focus {
        border: none;
        padding: 0 1;
        height: 1;
        min-height: 1;
        content-align: center top;
        text-align: center;
    }

    FriTapWizardModal .button-row Button * {
        padding: 0 0;
        margin: 0 0;
    }

    FriTapWizardModal .key-hints {
        text-align: center;
        color: $text-muted;
        margin-top: 0;
        height: auto;
    }
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    def action_cancel(self) -> None:
        """Dismiss the modal with no result."""
        self.dismiss(None)

    def on_mount(self) -> None:
        """Auto-focus the first focusable widget."""
        self._auto_focus()

    def _auto_focus(self) -> None:
        """Focus the first Input or Button found."""
        try:
            self.query(Input).first().focus()
        except Exception:
            try:
                self.query(Button).first().focus()
            except Exception:
                pass

    def _find_primary_button(self) -> Button | None:
        """Return the primary button, or the first button if none is primary."""
        try:
            return self.query_one("Button.-primary", Button)
        except Exception:
            pass
        try:
            return self.query_one(Button)
        except Exception:
            return None

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in an Input triggers the primary button."""
        button = self._find_primary_button()
        if button is not None:
            button.press()
