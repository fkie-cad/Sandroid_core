"""Widget Refresh Controller for TUI.

This controller manages widget refresh operations, extracted from the
monolithic app.py to follow Single Responsibility Principle.

Responsibilities:
- Refresh status bar with current state
- Refresh menu panel with current items
- Perform full UI refresh

Usage:
    from sandroid.tui.controllers import WidgetRefreshController

    controller = WidgetRefreshController(
        query_widget=app.query_one,
        query_from_screen=lambda w_id, w_type: app.screen.query_one(w_id, w_type),
        is_main_screen=lambda: isinstance(app.screen, MainScreen),
        refresh_app=app.refresh,
        refresh_screen=lambda: app.screen.refresh(layout=True),
    )

    # Refresh all widgets
    controller.refresh_all()
"""

import logging
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class WidgetRefreshController:
    """Controller for widget refresh operations.

    This controller handles all widget refresh-related operations, decoupled from
    the TUI layer through callback injection. This enables:
    - Independent unit testing without TUI dependencies
    - Clear separation of refresh logic from UI rendering
    - Consistent refresh behavior across the application

    Example:
        controller = WidgetRefreshController(
            query_widget=lambda w_id, w_type: None,
            query_from_screen=lambda w_id, w_type: None,
            is_main_screen=lambda: True,
            refresh_app=lambda **kwargs: None,
            refresh_screen=lambda: None,
        )

        # Refresh all widgets
        controller.refresh_all()
    """

    def __init__(
        self,
        query_widget: Callable[[str, type[T]], T] | None = None,
        query_from_screen: Callable[[str, type[T]], T] | None = None,
        is_main_screen: Callable[[], bool] | None = None,
        refresh_app: Callable[..., None] | None = None,
        refresh_screen: Callable[[], None] | None = None,
    ):
        """Initialize WidgetRefreshController with UI callbacks.

        Args:
            query_widget: Callback to query a widget by ID and type (app.query_one)
            query_from_screen: Callback to query a widget from screen
            is_main_screen: Callback to check if current screen is MainScreen
            refresh_app: Callback to refresh the app (app.refresh)
            refresh_screen: Callback to refresh the current screen
        """
        self._query_widget = query_widget
        self._query_from_screen = query_from_screen
        self._is_main_screen = is_main_screen or (lambda: True)
        self._refresh_app = refresh_app
        self._refresh_screen = refresh_screen

    def _get_widget(self, widget_id: str, widget_type: type[T]) -> T | None:
        """Get a widget by ID and type, with fallback to screen query.

        Args:
            widget_id: The widget ID (e.g., "#status-bar")
            widget_type: The widget type class

        Returns:
            The widget if found, None otherwise
        """
        widget = None

        # Try direct query first
        if self._query_widget:
            try:
                widget = self._query_widget(widget_id, widget_type)
            except Exception:
                pass

        # Fallback to screen query if on MainScreen
        if widget is None and self._query_from_screen and self._is_main_screen():
            try:
                widget = self._query_from_screen(widget_id, widget_type)
            except Exception:
                pass

        return widget

    def _update_widget(
        self, widget_id: str, widget_type: type[T], update_method: str
    ) -> None:
        """Find a widget, call its update method if available, and refresh it.

        Args:
            widget_id: Widget CSS selector (e.g., "#status-bar").
            widget_type: Widget class type.
            update_method: Name of the method to call before refresh.
        """
        widget = self._get_widget(widget_id, widget_type)
        if widget:
            if hasattr(widget, update_method):
                getattr(widget, update_method)()
            widget.refresh()

    def refresh_all(self) -> None:
        """Force a complete UI refresh after state changes.

        Updates status bar, menu panel, footer, and forces layout refresh.
        """
        self.refresh_status_bar()
        self.refresh_menu()
        self.refresh_footer()

        try:
            if self._refresh_screen:
                self._refresh_screen()
            if self._refresh_app:
                self._refresh_app(layout=True)
        except Exception:
            pass

    def refresh_status_bar(self) -> None:
        """Update the status bar with current state."""
        from sandroid.tui.widgets import StatusBar

        self._update_widget("#status-bar", StatusBar, "update_from_toolbox")

    def refresh_menu(self) -> None:
        """Refresh the menu panel to reflect current state.

        This method updates the menu to show/hide dynamic items like
        'resume objection session' based on current state.
        """
        from sandroid.tui.widgets import MenuPanel

        self._update_widget("#menu-panel", MenuPanel, "update_menu")

    def refresh_footer(self) -> None:
        """Refresh the SandroidFooter widget to restore it after modal dismissal."""
        from sandroid.tui.widgets import SandroidFooter

        widget = self._get_widget("SandroidFooter", SandroidFooter)
        if widget:
            widget.refresh(layout=True)


__all__ = [
    "WidgetRefreshController",
]
