"""Help screen overlay for Sandroid TUI."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import ScrollableContainer, Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from sandroid.core.enums import ViewMode
from sandroid.core.menu_controller import ActionCategory, MenuController
from sandroid.tui.screens.command_palette import _format_key_display


class HelpScreen(ModalScreen):
    """Modal help screen showing all available shortcuts.

    Displays:
    - All actions for current view grouped by category
    - Navigation shortcuts
    - TUI-specific bindings

    Colors are pulled from the current theme.
    """

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
        background: rgba(5, 8, 17, 0.85);
    }

    #help-container {
        width: 80;
        height: auto;
        max-height: 36;
        background: #0d1117;
        border: solid #2f81f7;
        padding: 1 2;
    }

    #help-title {
        text-align: center;
        text-style: bold;
        color: #58a6ff;
        margin-bottom: 1;
        width: 100%;
    }

    #help-content {
        height: auto;
        max-height: 28;
        background: #161b22;
        border: solid #30363d;
        padding: 0 1;
    }

    #help-content:focus {
        border: solid #2f81f7;
    }

    #help-text {
        width: 100%;
    }

    .help-footer {
        text-align: center;
        color: #8b949e;
        margin-top: 1;
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", priority=True),
        Binding("question_mark", "dismiss", "Close", priority=True),
        Binding("q", "dismiss", "Close", priority=True),
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
    ]

    def __init__(
        self,
        current_view: str | ViewMode = ViewMode.FORENSIC,
        name: str = None,
        id: str = None,
        classes: str = None,
    ):
        """Initialize the help screen.

        Args:
            current_view: Current view mode for context-aware help
            name: Screen name
            id: Screen ID
            classes: CSS classes
        """
        super().__init__(name=name, id=id, classes=classes)
        # Ensure current_view is a string for MenuController compatibility
        self.current_view = (
            current_view.value if isinstance(current_view, ViewMode) else current_view
        )
        self._controller = MenuController.get()

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for help screen rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",
            "key": "#ff00ff",
            "text": "#e5e9f0",
            "text_muted": "#8f9bb3",
            ViewMode.FORENSIC: "#2dd4bf",
            ViewMode.MALWARE: "#fb7185",
            ViewMode.SECURITY: "#facc15",
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["key"] = theme.key_color
                colors["text"] = theme.text
                colors["text_muted"] = theme.text_muted
                colors[ViewMode.FORENSIC] = theme.forensic_color
                colors[ViewMode.MALWARE] = theme.malware_color
                colors[ViewMode.SECURITY] = theme.security_color
        except Exception:
            pass

        return colors

    def compose(self) -> ComposeResult:
        """Create the help screen layout."""
        with Vertical(id="help-container"):
            yield Static(self._build_title(), id="help-title")
            with ScrollableContainer(id="help-content"):
                yield Static(self._build_help_content(), id="help-text")
            yield Static(
                "[dim]?/q/Esc=Close, j/k=Scroll, g/G=Top/Bottom[/dim]",
                classes="help-footer",
            )

    def _build_title(self) -> str:
        """Build the help title."""
        colors = self._get_theme_colors()
        view_colors = {
            ViewMode.FORENSIC.value: colors[ViewMode.FORENSIC],
            ViewMode.MALWARE.value: colors[ViewMode.MALWARE],
            ViewMode.SECURITY.value: colors[ViewMode.SECURITY],
        }
        color = view_colors.get(self.current_view, colors["primary"])
        return f"[bold {color}]=== {self.current_view.upper()} View - Keyboard Shortcuts ===[/]"

    def _build_help_content(self) -> str:
        """Build the help content from MenuController.

        Returns:
            Formatted help string for Textual
        """
        colors = self._get_theme_colors()
        lines = []

        # Get actions grouped by category
        by_category = self._controller.get_actions_by_category(self.current_view)

        # Define display order for categories
        # Note: NAVIGATION excluded - we have a custom TUI Navigation section below
        category_order = [
            ActionCategory.RECORDING,
            ActionCategory.SPOTLIGHT,
            ActionCategory.FILES,
            ActionCategory.EMULATOR,
            ActionCategory.ANALYSIS,
            ActionCategory.NETWORK,
        ]

        for category in category_order:
            if category not in by_category:
                continue

            actions = by_category[category]
            if not actions:
                continue

            # Category header (using theme primary color)
            cat_name = category.name.replace("_", " ").title()
            lines.append("")
            lines.append(f"[bold {colors['primary']}]=== {cat_name} ===[/]")

            # Sort actions by key
            for action in sorted(actions, key=lambda a: a.key.lower()):
                key_display = _format_key_display(action.key)

                # Build description with requirements
                desc = action.display_name
                if action.description:
                    desc = f"{action.display_name} - {action.description}"

                reqs = []
                if action.requires_frida:
                    reqs.append("Frida")
                if action.requires_spotlight:
                    reqs.append("Spotlight")
                if reqs:
                    desc += f" [dim](requires: {', '.join(reqs)})[/]"

                # Use single brackets with theme key color
                lines.append(f"  [bold {colors['key']}]\\[{key_display:>5}][/]  {desc}")

        # Add TUI-specific navigation section
        lines.append("")
        lines.append(f"[bold {colors['primary']}]=== TUI Navigation ===[/]")
        lines.append(f"  [bold {colors['key']}]\\[    j][/]  Scroll down one line")
        lines.append(f"  [bold {colors['key']}]\\[Ctrl+K][/]  Scroll up one line")
        lines.append(f"  [bold {colors['key']}]\\[Ctrl+D][/]  Scroll down half page")
        lines.append(f"  [bold {colors['key']}]\\[Ctrl+U][/]  Scroll up half page")
        lines.append(f"  [bold {colors['key']}]\\[ Home][/]  Jump to top")
        lines.append(f"  [bold {colors['key']}]\\[End/G][/]  Jump to bottom")
        lines.append(
            f"  [bold {colors['key']}]\\[  TAB][/]  Switch view (Forensic/Malware/Security)"
        )
        lines.append(f"  [bold {colors['key']}]\\[    ?][/]  Show this help")
        lines.append(f"  [bold {colors['key']}]\\[Ctrl+P][/]  Open command palette")
        lines.append(
            f"  [bold {colors['key']}]\\[  ESC][/]  Cancel/Back (in dialogs) or Quit confirmation (main)"
        )
        lines.append(f"  [bold {colors['key']}]\\[    q][/]  Quit Sandroid immediately")
        lines.append(f"  [bold {colors['key']}]\\[Ctrl+C][/]  Quit with confirmation")
        lines.append(f"  [bold {colors['key']}]\\[    ,][/]  Settings")

        # Add tips
        lines.append("")
        lines.append(f"[bold {colors['primary']}]=== Tips ===[/]")
        lines.append("  - Press the same key to toggle background tasks")
        lines.append("  - Disabled actions show in [dim]dim text[/]")
        lines.append("  - Status bar shows current state")
        lines.append("  - Activity log shows background task output")
        lines.append("")
        lines.append(f"[bold {colors['primary']}]=== Copy/Paste ===[/]")
        lines.append(
            f"  [bold {colors['key']}]\\[    Y][/]  Copy activity log to clipboard (vim yank)"
        )
        lines.append(
            "  - Hold [bold]Shift[/] (or [bold]Option[/] on macOS) while selecting text"
        )
        lines.append("  - Then copy: Cmd+C (macOS) or Ctrl+Shift+C (Linux/Windows)")
        lines.append("  - Paste: Cmd+V (macOS) or Ctrl+Shift+V (Linux/Windows)")

        return "\n".join(lines)

    def action_scroll_down(self) -> None:
        """Scroll down by one line."""
        content = self.query_one("#help-content", ScrollableContainer)
        content.scroll_relative(y=1)

    def action_scroll_up(self) -> None:
        """Scroll up by one line."""
        content = self.query_one("#help-content", ScrollableContainer)
        content.scroll_relative(y=-1)

    def action_scroll_top(self) -> None:
        """Scroll to top."""
        content = self.query_one("#help-content", ScrollableContainer)
        content.scroll_home()

    def action_scroll_bottom(self) -> None:
        """Scroll to bottom."""
        content = self.query_one("#help-content", ScrollableContainer)
        content.scroll_end()

    def action_dismiss(self) -> None:
        """Dismiss the help screen and refresh the main screen."""
        # Schedule a refresh of the app after dismissal to fix display issues
        self.app.call_later(self._refresh_app)
        self.dismiss()

    def _refresh_app(self) -> None:
        """Refresh the app display after modal closes."""
        try:
            # Force a full refresh of the screen
            self.app.refresh(layout=True)
        except Exception:
            pass
