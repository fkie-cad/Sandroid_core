"""TUI utilities for Sandroid."""

from .box_renderer import box_line, make_box_line, strip_color_codes
from .clipboard import copy_to_clipboard, is_clipboard_available
from .compact import apply_compact_widgets
from .monitor_process_wrapper import MonitorProcessWrapper
from .recording_wrapper import RecordingWrapper

__all__ = [
    "MonitorProcessWrapper",
    "RecordingWrapper",
    "apply_compact_widgets",
    "box_line",
    "copy_to_clipboard",
    "is_clipboard_available",
    "make_box_line",
    "strip_color_codes",
]
