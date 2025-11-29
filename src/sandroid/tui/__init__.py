"""Textual-based TUI for Sandroid.

This module provides a modern, interactive terminal user interface (TUI)
built on the Textual framework. It offers a split-pane layout with:
- Menu navigation on the left
- Background activity output on the right
- Real-time event updates
- Keyboard-driven interaction

Usage:
    from sandroid.tui import SandroidTUI
    app = SandroidTUI()
    app.run()

The TUI integrates with the event system to receive real-time updates
from background tasks without blocking the menu interface.
"""

from sandroid.tui.app import SandroidTUI

__all__ = ["SandroidTUI"]
