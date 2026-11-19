"""Activity log widget for background task output."""

import re
import time
from collections import deque
from datetime import datetime

from rich.highlighter import ReprHighlighter
from textual.message import Message
from textual.widgets import RichLog

from sandroid._version import __version__
from sandroid.core.console import SANDROID_LOGO
from sandroid.core.enums import ViewMode
from sandroid.tui.themes import fixed_color


class _LogHighlighter(ReprHighlighter):
    """Rich's repr highlighter without the path / file name colouring.

    It painted every device and results path in magenta -- on the dark
    themes that reads as red, so a normal "Pulled /data/... to ..." INFO
    line looked like an error (E2E finding). Numbers, URLs, quoted strings
    etc. keep their colours.
    """

    _DROP = frozenset({"repr.path", "repr.filename"})

    def highlight(self, text) -> None:
        super().highlight(text)
        text.spans = [span for span in text.spans if span.style not in self._DROP]


class ActivityLog(RichLog):
    """Log widget for displaying background task output.

    Features:
    - Auto-scrolling with new content
    - Rich markup support
    - Timestamp prefixing
    - Task started/stopped use fixed colors for consistent recognition
    - Other colors are pulled from the current theme
    - Every write posts :class:`ActivityLog.LineWritten` (the main screen's
      one-row log ticker mirrors it while the log drawer is closed)
    - Lines are wrapped to the log's *current* width: RichLog renders a
      line once, when written, and the log lives in a drawer that is hidden
      (width 0) most of the time -- so every line written while it was
      closed wrapped at ``min_width`` (20 columns at 200; E2E finding). The
      last ``REFLOW_ENTRIES`` writes are kept and re-rendered whenever the
      width changes (the drawer opens, the terminal is resized); writes
      while it is hidden are only rendered then.
    """

    #: Writes kept for re-rendering at a new width (the plain-text copy for
    #: the clipboard keeps everything).
    REFLOW_ENTRIES = 1000

    class LineWritten(Message):
        """A line was written; ``content`` is what was passed to write()."""

        def __init__(self, content) -> None:
            super().__init__()
            self.content = content

    def __init__(self, **kwargs):
        """Initialize the activity log."""
        # min_width: wrap to the drawer's width (RichLog's default 78 made
        # lines wider than an 80-column drawer, hence a horizontal scrollbar).
        kwargs.setdefault("min_width", 20)
        super().__init__(
            highlight=True, markup=True, wrap=True, auto_scroll=True, **kwargs
        )
        self.highlighter = _LogHighlighter()
        # Store plain text copies of all log lines for clipboard export
        self._plain_lines: list[str] = []
        # (content, width, expand, shrink) of the recent writes (_reflow).
        self._entries: deque[tuple] = deque(maxlen=self.REFLOW_ENTRIES)
        self._rendered_width = 0
        self._reflow_pending = False
        # (normalized text, monotonic time) of the last few log lines, for
        # dropping the same message arriving again via a second channel.
        self._recent: deque[tuple[str, float]] = deque(maxlen=24)
        # Recurring warnings/errors: key -> [last shown (monotonic), number
        # suppressed since]. One error firing per network flow (a traceback
        # each time) used to drown the drawer and the ticker.
        self._repeats: dict[str, list[float]] = {}

    #: Seconds within which an identical (normalized) line is a duplicate.
    DEDUP_WINDOW = 3.0
    _TOOL_PREFIX_RE = re.compile(r"^(?:\[[*+!-]\]\s*)+")
    _MARKUP_RE = re.compile(r"\[/?[^\]]*\]")

    #: Seconds a recurring warning/error (same text up to numbers and
    #: addresses) is shown at most once; the next copy carries the count.
    REPEAT_WINDOW = 60.0
    _VOLATILE_RE = re.compile(r"0x[0-9a-fA-F]+|\d+")

    @classmethod
    def _repeat_key(cls, message: str) -> str:
        """Identity of a warning/error regardless of ids, PIDs and times.

        A multi-line message (a traceback) is keyed by its first and last
        line: the same exception from the same place is one problem.
        """
        lines = [ln for ln in str(message).strip().splitlines() if ln.strip()]
        if not lines:
            return ""
        text = lines[0] if len(lines) == 1 else f"{lines[0]} … {lines[-1]}"
        return cls._VOLATILE_RE.sub("#", cls._normalize(text))

    def _repeat_suffix(self, message: str) -> str | None:
        """None to drop a recurring warning/error, else a suffix to append.

        The first copy is shown; further copies within ``REPEAT_WINDOW`` are
        counted, and the next copy after it says how many were folded.
        """
        key = self._repeat_key(message)
        if not key:
            return ""
        now = time.monotonic()
        entry = self._repeats.get(key)
        if entry is not None and now - entry[0] <= self.REPEAT_WINDOW:
            entry[1] += 1
            return None
        folded = int(entry[1]) if entry is not None else 0
        self._repeats[key] = [now, 0]
        if len(self._repeats) > 256:
            oldest = min(self._repeats, key=lambda k: self._repeats[k][0])
            self._repeats.pop(oldest, None)
        if folded:
            return f" [dim](+{folded} more like this in the last minute)[/dim]"
        return ""

    @classmethod
    def _normalize(cls, message: str) -> str:
        text = cls._TOOL_PREFIX_RE.sub("", str(message).strip())
        text = cls._MARKUP_RE.sub("", text)
        return " ".join(text.split())

    def _is_repeat(self, message: str) -> bool:
        """True if ``message`` was already shown within ``DEDUP_WINDOW``.

        Many tools reach the log twice or three times -- e.g. every friTap
        line arrives as task output ("FriTap: x"), as its own Python log
        record ("INFO: x") and with its "[*] " prefix ("FriTap: [*] x").
        Level, source label and "[*]"/"[+]" prefixes are ignored when
        comparing, so only the first copy is shown.
        """
        key = self._normalize(message)
        if not key:
            return False
        now = time.monotonic()
        for seen, at in self._recent:
            if seen == key and now - at <= self.DEDUP_WINDOW:
                return True
        self._recent.append((key, now))
        return False

    def write(
        self,
        content,
        width=None,
        expand=False,
        shrink=True,
        scroll_end=None,
    ) -> None:
        """Write content to the log and store plain text copy.

        Args:
            content: Rich markup content to write
            width: Width to render content (None = auto)
            expand: Expand content to fill width
            shrink: Shrink content if larger than width
            scroll_end: Scroll to end after write (None = use auto_scroll)
        """
        # Store plain text version (strip Rich markup)
        plain = re.sub(r"\[/?[^\]]*\]", "", str(content))
        self._plain_lines.append(plain)
        self._entries.append((content, width, expand, shrink))
        width_now = self._content_width()
        if width_now <= 0:
            # Hidden (the closed drawer): render when it gets a width.
            self._reflow_pending = True
        elif self._reflow_pending or width_now != self._rendered_width:
            self._reflow()
        else:
            super().write(
                content,
                width=width or width_now,
                expand=expand,
                shrink=shrink,
                scroll_end=scroll_end,
            )
        self.post_message(self.LineWritten(content))

    def _content_width(self) -> int:
        """The width lines wrap to now (0 while hidden or not laid out)."""
        if not getattr(self, "_size_known", True):
            return 0
        try:
            return max(0, self.scrollable_content_region.width)
        except Exception:
            return 0

    def _reflow(self) -> None:
        """Re-render the kept writes at the current width."""
        width_now = self._content_width()
        if width_now <= 0:
            self._reflow_pending = True
            return
        self._reflow_pending = False
        self._rendered_width = width_now
        at_end = self.is_vertical_scroll_end or not self.lines
        RichLog.clear(self)
        for content, width, expand, shrink in self._entries:
            RichLog.write(
                self, content, width=width or width_now, expand=expand,
                shrink=shrink,
                scroll_end=False,
            )  # fmt: skip
        if at_end and self.auto_scroll:
            self.scroll_end(animate=False, immediate=True)

    def on_resize(self, _event) -> None:
        # After RichLog's own handler (it marks the size known first).
        self.call_after_refresh(self._reflow_if_needed)

    def on_show(self, _event) -> None:
        self.call_after_refresh(self._reflow_if_needed)

    def reflow_when_shown(self, tries: int = 5) -> None:
        """Render kept lines as soon as the log has a width again.

        The owner calls this when it shows the log (the drawer opens). It
        retries after each refresh until layout gave the log a width, so a
        line written while hidden can never be lost.
        """
        if self._content_width() > 0:
            self._reflow_if_needed()
            return
        if tries > 0:
            self.call_after_refresh(self.reflow_when_shown, tries - 1)

    def _reflow_if_needed(self) -> None:
        width_now = self._content_width()
        if width_now > 0 and (
            self._reflow_pending or width_now != self._rendered_width
        ):
            self._reflow()

    def clear(self) -> None:
        """Clear the log content."""
        self._plain_lines.clear()
        self._entries.clear()
        self._reflow_pending = False
        super().clear()

    def _get_theme_colors(self) -> dict:
        """Get colors from current theme.

        Returns:
            Dict with color keys for log rendering
        """
        # Default colors (Midnight Cyan)
        colors = {
            "primary": "#38bdf8",
            "success": "#00ff00",
            "error": "#fb7185",
            "warning": "#facc15",
            "info": "#7dd3fc",
            "text_muted": "#8f9bb3",
            ViewMode.FORENSIC: "#2dd4bf",
            ViewMode.MALWARE: "#fb7185",
            ViewMode.SECURITY: "#facc15",
            "key": "#ff00ff",
        }

        try:
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                colors["primary"] = theme.primary
                colors["success"] = theme.success
                colors["error"] = theme.error
                colors["warning"] = theme.warning
                colors["info"] = theme.secondary
                colors["text_muted"] = theme.text_muted
                colors[ViewMode.FORENSIC] = theme.forensic_color
                colors[ViewMode.MALWARE] = theme.malware_color
                colors[ViewMode.SECURITY] = theme.security_color
                colors["key"] = theme.key_color
        except Exception:
            pass

        return colors

    def show_welcome(self) -> None:
        """Display the Sandroid logo and version at startup.

        Uses logo colors in this priority:
        1. Config overrides (tui.logo_color, tui.logo_text_color)
        2. Current theme's logo colors
        3. Default fallback colors
        """
        # Get logo colors from theme (with fallbacks)
        logo_color = "#00ff00"  # Default bright green
        logo_text_color = "#ffffff"  # Default white

        try:
            # Try to get theme from the app
            if hasattr(self.app, "sandroid_theme"):
                theme = self.app.sandroid_theme
                logo_color = theme.logo_color
                logo_text_color = theme.logo_text_color

            # Check for config overrides (highest priority)
            if hasattr(self.app, "sandroid_config"):
                config = self.app.sandroid_config
                if hasattr(config, "tui"):
                    if config.tui.logo_color:
                        logo_color = config.tui.logo_color
                    if config.tui.logo_text_color:
                        logo_text_color = config.tui.logo_text_color
        except Exception:
            pass  # Use defaults

        # Display logo with theme colors
        for line in SANDROID_LOGO.splitlines():
            if "Sandroid" in line:
                # Highlight "Sandroid" text differently
                before, after = line.split("Sandroid", 1)
                self.write(
                    f"[{logo_color}]{before}[/][bold {logo_text_color}]Sandroid[/][{logo_color}]{after}[/]"
                )
            else:
                self.write(f"[{logo_color}]{line}[/]")

        # Display version (using theme primary color)
        primary_color = "#38bdf8"  # Default cyan
        try:
            if hasattr(self.app, "sandroid_theme"):
                primary_color = self.app.sandroid_theme.primary
        except Exception:
            pass

        self.write("")
        self.write(f"[bold {primary_color}]Version {__version__}[/]")
        self.write("[dim]Android Forensic Analysis Framework[/]")
        self.write("")
        self.write("[dim]─" * 40 + "[/]")
        self.write("")

    def log_message(self, message: str, task_name: str = None) -> None:
        """Log a message with optional task name prefix.

        Args:
            message: The message to log
            task_name: Optional task name for prefix
        """
        if self._is_repeat(message):
            return
        colors = self._get_theme_colors()
        timestamp = datetime.now().strftime("%H:%M:%S")
        if task_name:
            self.write(
                f"[{colors['text_muted']}]{timestamp}[/] [{colors['primary']}]{task_name}:[/] {message}"
            )
        else:
            self.write(f"[{colors['text_muted']}]{timestamp}[/] {message}")

    def log_task_started(self, task_name: str, app_name: str = None) -> None:
        """Log a task started event.

        Uses ``fixed_color`` for consistent "running" recognition across themes.

        Args:
            task_name: Name of the task
            app_name: Optional app name the task is running on
        """
        if app_name:
            self.write(
                f"[{fixed_color('running')} bold]>>> Started: {task_name} on {app_name}[/]"
            )
        else:
            self.write(f"[{fixed_color('running')} bold]>>> Started: {task_name}[/]")

    def log_task_updated(self, task_name: str) -> None:
        """Log a task display-name change (not a restart)."""
        self.write(f"[{fixed_color('running')}][~] {task_name}[/]")

    def log_task_stopped(self, task_name: str) -> None:
        """Log a task stopped event.

        A normal stop is not an error: muted, not red (red is for ERROR
        lines). The same stop reported twice (task service + controller) is
        shown once.

        Args:
            task_name: Name of the task
        """
        line = f"<<< Stopped: {task_name}"
        if self._is_repeat(line):
            return
        muted = self._get_theme_colors()["text_muted"]
        self.write(f"[{muted} bold]{line}[/]")

    def _log_with_level(
        self, level_key: str, label: str, message: str, bold: bool = True
    ) -> None:
        """Log a message with a colored level prefix.

        Args:
            level_key: Key into theme colors (e.g. 'error', 'warning')
            label: Display label (e.g. 'ERROR', 'WARNING')
            message: The message to log
            bold: Whether to bold the label
        """
        if self._is_repeat(message):
            return
        suffix = ""
        if level_key in ("error", "warning"):
            suffix = self._repeat_suffix(message)
            if suffix is None:
                return
        colors = self._get_theme_colors()
        timestamp = datetime.now().strftime("%H:%M:%S")
        style = f"{colors[level_key]} bold" if bold else colors[level_key]
        self.write(
            f"[{colors['text_muted']}]{timestamp}[/] [{style}]{label}:[/] "
            f"{message}{suffix}"
        )

    def log_error(self, message: str) -> None:
        """Log an error message.

        Args:
            message: The error message
        """
        self._log_with_level("error", "ERROR", message)

    def log_warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message: The warning message
        """
        self._log_with_level("warning", "WARNING", message)

    def log_success(self, message: str) -> None:
        """Log a success message.

        Args:
            message: The success message
        """
        self._log_with_level("success", "SUCCESS", message)

    def log_info(self, message: str) -> None:
        """Log an info message.

        Args:
            message: The info message
        """
        self._log_with_level("info", "INFO", message, bold=False)

    def log_forensic(self, message: str) -> None:
        """Log a forensic-related message with warning_status color.

        Uses the same color as the APKs indicator in the header for consistency.

        Args:
            message: The forensic message
        """
        colors = self._get_theme_colors()
        timestamp = datetime.now().strftime("%H:%M:%S")
        forensic_color = fixed_color("warning_status")
        self.write(
            f"[{colors['text_muted']}]{timestamp}[/] [{forensic_color}]INFO:[/] {message}"
        )

    def log_view_change(self, new_view: str | ViewMode) -> None:
        """Log a view change event.

        Args:
            new_view: The new view (ViewMode or string)
        """
        colors = self._get_theme_colors()
        view_colors = {
            ViewMode.FORENSIC.value: colors[ViewMode.FORENSIC],
            ViewMode.MALWARE.value: colors[ViewMode.MALWARE],
            ViewMode.SECURITY.value: colors[ViewMode.SECURITY],
        }
        # Get view string for lookup
        view_str = (
            new_view.value if isinstance(new_view, ViewMode) else new_view.lower()
        )
        color = view_colors.get(view_str, colors["primary"])
        self.write(f"[{color} bold]>>> Switched to {view_str.upper()} view[/]")

    def log_action_triggered(self, action_name: str, key: str) -> None:
        """Log when an action is triggered.

        Args:
            action_name: Name of the action
            key: Key that triggered it
        """
        colors = self._get_theme_colors()
        self.write(
            f"[{colors['text_muted']}]Action triggered:[/] [bold {colors['key']}]\\[{key}][/] {action_name}"
        )

    def log_validation_error(self, message: str) -> None:
        """Log a validation error (action preconditions not met).

        Args:
            message: The validation error message
        """
        colors = self._get_theme_colors()
        self.write(f"[{colors['warning']}]! {message}[/]")

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

    def get_plain_text(self, max_lines: int = 0) -> str:
        """Get log content as plain text (Rich markup stripped).

        Args:
            max_lines: Maximum number of lines to return (0 = all)

        Returns:
            Plain text content of the log
        """
        lines = self._plain_lines.copy()

        if max_lines > 0:
            lines = lines[-max_lines:]

        return "\n".join(lines)

    def get_line_count(self) -> int:
        """Get the number of lines in the log.

        Returns:
            Number of log lines
        """
        return len(self._plain_lines)
