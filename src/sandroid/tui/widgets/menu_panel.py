"""Menu panel widget using MenuController."""

from textual.containers import ScrollableContainer
from textual.reactive import reactive
from textual.widgets import Static

from sandroid.core.enums import ViewMode
from sandroid.core.menu_controller import MenuController


class MenuPanel(ScrollableContainer):
    """Scrollable left-column panel.

    The full per-category action list has been retired — actions now live
    behind the ``?`` keybinding editor and the ``Ctrl+Shift+P`` command
    palette. This panel now renders a short static placeholder, leaving room
    for the expanded bottom strip and a future dashboard. The ``#menu-panel``
    id and the scroll methods are kept because other code (vim j/k handlers,
    focus routing) still references them.
    """

    current_view = reactive(ViewMode.FORENSIC.value)

    def __init__(self, **kwargs):
        """Initialize the menu panel."""
        super().__init__(**kwargs)
        self._controller = MenuController.get()

    def compose(self):
        """Compose the menu panel."""
        yield Static("Sandroid Interactive Menu", id="menu-title")
        yield Static("", id="menu-content")

    def on_mount(self) -> None:
        """Update menu on mount."""
        self.update_menu()

    def watch_current_view(self, view: str) -> None:
        """React to view changes."""
        self.update_menu()

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for menu rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",  # Headers
            "key": "#ff00ff",  # Key brackets
            "text": "#e5e9f0",  # Main text
            "text_muted": "#8f9bb3",  # Dimmed text
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["key"] = theme.key_color
                colors["text"] = theme.text
                colors["text_muted"] = theme.text_muted
        except Exception:
            pass

        return colors

    def update_menu(self, view: str | ViewMode = None) -> None:
        """Update menu content based on current view.

        Args:
            view: Optional view to switch to (ViewMode or string)
        """
        if view:
            # Ensure view is a string for MenuController compatibility
            self.current_view = view.value if isinstance(view, ViewMode) else view

        content = self._build_menu_content()
        try:
            menu_content = self.query_one("#menu-content", Static)
            menu_content.update(content)
        except Exception:
            pass

    def _build_menu_content(self) -> str:
        """Build the static placeholder shown in the left column.

        The per-category action list was retired in favour of the ``?``
        keybinding editor and the command palette, so this returns a short
        theme-coloured placeholder instead.

        Returns:
            Formatted placeholder string for Textual
        """
        colors = self._get_theme_colors()
        key = colors["key"]
        text = colors["text"]
        muted = colors["text_muted"]

        def hint(combo: str, label: str) -> str:
            """Render a single ``[combo]  label`` hint line."""
            return f"  [bold {key}]\\[{combo}][/]  [{text}]{label}[/]"

        lines = [
            "",
            f"[bold {colors['primary']}]Menu retired — actions moved.[/]",
            "",
            hint("?", "actions & keybindings"),
            hint("Ctrl+⇧P", "command palette"),
            hint("Ctrl+B", "bottom panel (Spotlight · Mitmproxy · Snapshots)"),
            "",
            f"[{muted}]This left column is a placeholder for a future "
            f"dashboard.[/]",
            "",
        ]

        return "\n".join(lines)

    def scroll_down_line(self) -> None:
        """Scroll down by one line (vim j key)."""
        self.scroll_relative(y=1)

    def scroll_up_line(self) -> None:
        """Scroll up by one line (vim k key)."""
        self.scroll_relative(y=-1)

    def scroll_to_top(self) -> None:
        """Scroll to top (vim g key)."""
        self.scroll_home()

    def scroll_to_bottom(self) -> None:
        """Scroll to bottom (vim G key)."""
        self.scroll_end()
