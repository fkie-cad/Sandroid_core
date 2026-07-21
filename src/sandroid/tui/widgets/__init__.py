"""Sandroid TUI widgets.

Reusable widget components for the Sandroid TUI.
"""

from sandroid.tui.widgets.activity_log import ActivityLog
from sandroid.tui.widgets.diff_view import DiffView
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.fritap_panel import FriTapPanel
from sandroid.tui.widgets.loading_spinner import LoadingSpinner
from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel
from sandroid.tui.widgets.sandroid_footer import SandroidFooter
from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel
from sandroid.tui.widgets.spotlight_panel import SpotlightPanel
from sandroid.tui.widgets.status_bar import StatusBar

__all__ = [
    "ActivityLog",
    "DiffView",
    "FilesPanel",
    "FriTapPanel",
    "LoadingSpinner",
    "MitmproxyPanel",
    "SandroidFooter",
    "SnapshotsPanel",
    "SpotlightPanel",
    "StatusBar",
]
