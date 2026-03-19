"""Sandroid TUI widgets.

Reusable widget components for the Sandroid TUI.
"""

from sandroid.tui.widgets.activity_log import ActivityLog
from sandroid.tui.widgets.loading_spinner import LoadingSpinner
from sandroid.tui.widgets.menu_panel import MenuPanel
from sandroid.tui.widgets.minimized_task_bar import MinimizedTaskBar
from sandroid.tui.widgets.sandroid_footer import SandroidFooter
from sandroid.tui.widgets.status_bar import StatusBar

__all__ = [
    "ActivityLog",
    "LoadingSpinner",
    "MenuPanel",
    "MinimizedTaskBar",
    "SandroidFooter",
    "StatusBar",
]
