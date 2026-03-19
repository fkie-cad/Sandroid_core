"""Textual-based TUI for Sandroid.

This module provides a modern, interactive terminal user interface (TUI)
built on the Textual framework. It offers a mitmproxy-like experience with:

Features:
- Split-pane layout with menu and activity log
- Three view modes: Forensic, Malware, Security
- Vim-style navigation (j/k/g/G)
- Help overlay (?) showing all shortcuts
- Command palette (Ctrl+P) for fuzzy search
- Theme switching (Ctrl+T) with 8 themes
- Native modal dialogs (no Rich mode switching)
- Real-time background task monitoring
- Keyboard-driven interaction

Usage:
    from sandroid.tui import SandroidTUI
    app = SandroidTUI(action_queue=action_q)
    app.run()

Or use the convenience function:
    from sandroid.tui import run_tui
    run_tui(action_queue=action_q)

The TUI integrates with:
- MenuController for unified action handling
- EventBus for real-time background task updates
- Toolbox for application state management
- UIRequestBus for native modal dialogs
"""

from sandroid.tui.app import SandroidTUI, run_tui
from sandroid.tui.modal_manager import ModalManager
from sandroid.tui.themes import (
    THEME_ORDER,
    THEMES,
    Theme,
    get_next_theme,
    get_theme,
)

__all__ = [
    "THEMES",
    "THEME_ORDER",
    "ModalManager",
    "SandroidTUI",
    "Theme",
    "get_next_theme",
    "get_theme",
    "run_tui",
]
