"""Activity log widget for background task output."""

import re
from datetime import datetime

from textual.widgets import RichLog

from sandroid._version import __version__
from sandroid.core.console import SANDROID_LOGO
from sandroid.core.enums import ViewMode
from sandroid.tui.themes import FIXED_COLORS


class ActivityLog(RichLog):
    """Log widget for displaying background task output.

    Features:
    - Auto-scrolling with new content
    - Rich markup support
    - Timestamp prefixing
    - Task started/stopped use fixed colors for consistent recognition
    - Other colors are pulled from the current theme
    """

    def __init__(self, **kwargs):
        """Initialize the activity log."""
        super().__init__(
            highlight=True, markup=True, wrap=True, auto_scroll=True, **kwargs
        )
        # Store plain text copies of all log lines for clipboard export
        self._plain_lines: list[str] = []

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
        # Call parent write with all arguments
        super().write(
            content,
            width=width,
            expand=expand,
            shrink=shrink,
            scroll_end=scroll_end,
        )

    def clear(self) -> None:
        """Clear the log content."""
        self._plain_lines.clear()
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

        Uses FIXED_COLORS for consistent "running" recognition across themes.

        Args:
            task_name: Name of the task
            app_name: Optional app name the task is running on
        """
        if app_name:
            self.write(
                f"[{FIXED_COLORS['running']} bold]>>> Started: {task_name} on {app_name}[/]"
            )
        else:
            self.write(f"[{FIXED_COLORS['running']} bold]>>> Started: {task_name}[/]")

    def log_task_updated(self, task_name: str) -> None:
        """Log a task display-name change (not a restart)."""
        self.write(
            f"[{FIXED_COLORS['running']}][~] {task_name}[/]"
        )

    def log_task_stopped(self, task_name: str) -> None:
        """Log a task stopped event.

        Uses FIXED_COLORS for consistent "stopped" recognition across themes.

        Args:
            task_name: Name of the task
        """
        self.write(f"[{FIXED_COLORS['stopped']} bold]<<< Stopped: {task_name}[/]")

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
        colors = self._get_theme_colors()
        timestamp = datetime.now().strftime("%H:%M:%S")
        style = f"{colors[level_key]} bold" if bold else colors[level_key]
        self.write(
            f"[{colors['text_muted']}]{timestamp}[/] [{style}]{label}:[/] {message}"
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
        forensic_color = FIXED_COLORS.get("warning_status", "#ffaa00")
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
