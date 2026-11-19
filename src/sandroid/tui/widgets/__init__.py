"""Sandroid TUI widgets.

Reusable widget components for the Sandroid TUI.

``ChatPanel`` is resolved lazily (module ``__getattr__`` /
:func:`load_chat_panel_class`): it pulls in :mod:`sandroid.ai` and its optional
dependencies (``mcp``, ``openai``-compatible client, ...), and importing this
package must never fail on an install without those extras -- the rest of the
TUI has to start regardless.
"""

import logging

from sandroid.tui.widgets.activity_log import ActivityLog
from sandroid.tui.widgets.diff_view import DiffView
from sandroid.tui.widgets.files_panel import FilesPanel
from sandroid.tui.widgets.fritap_panel import FriTapPanel
from sandroid.tui.widgets.lens_shell import (
    LENSES,
    Inspector,
    InspectorContent,
    LensBar,
    LogDrawer,
    LogTicker,
    ScopeChanged,
    ShellHeader,
)
from sandroid.tui.widgets.loading_spinner import LoadingSpinner
from sandroid.tui.widgets.mitmproxy_panel import MitmproxyPanel
from sandroid.tui.widgets.network_panel import NetworkPanel
from sandroid.tui.widgets.sandroid_footer import SandroidFooter
from sandroid.tui.widgets.snapshots_panel import SnapshotsPanel
from sandroid.tui.widgets.spotlight_panel import SpotlightPanel
from sandroid.tui.widgets.status_bar import StatusBar
from sandroid.tui.widgets.timeline_lens import TimelineLens

logger = logging.getLogger(__name__)

#: Why the chat panel could not be imported (None = not tried / succeeded).
CHAT_PANEL_IMPORT_ERROR: str | None = None


def load_chat_panel_class() -> type | None:
    """Import and return ``ChatPanel``, or ``None`` if its deps are missing.

    The reason for a failure is stored in :data:`CHAT_PANEL_IMPORT_ERROR` so
    callers can show a placeholder explaining what to install.
    """
    global CHAT_PANEL_IMPORT_ERROR
    try:
        from sandroid.tui.widgets.chat_panel import ChatPanel
    except ImportError as e:
        CHAT_PANEL_IMPORT_ERROR = str(e)
        logger.info(f"AI chat panel unavailable (optional dependency missing): {e}")
        return None
    CHAT_PANEL_IMPORT_ERROR = None
    return ChatPanel


def __getattr__(name: str):
    if name == "ChatPanel":
        from sandroid.tui.widgets.chat_panel import ChatPanel

        return ChatPanel
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "LENSES",
    "ActivityLog",
    "ChatPanel",
    "DiffView",
    "FilesPanel",
    "FriTapPanel",
    "Inspector",
    "InspectorContent",
    "LensBar",
    "LoadingSpinner",
    "LogDrawer",
    "LogTicker",
    "MitmproxyPanel",
    "NetworkPanel",
    "SandroidFooter",
    "ScopeChanged",
    "ShellHeader",
    "SnapshotsPanel",
    "SpotlightPanel",
    "StatusBar",
    "TimelineLens",
]
