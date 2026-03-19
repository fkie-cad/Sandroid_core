"""Centralized formatting utilities for Sandroid.

This module provides shared color definitions and text formatting utilities
used across the codebase. It consolidates the previously duplicated Bcolors
class from multiple analysis modules into a single source of truth.

Usage:
    from sandroid.core.formatting import Colors, OutputFormatter

    # Using colors directly
    print(f"{Colors.OKGREEN}Success!{Colors.ENDC}")

    # Using formatter utilities
    header = OutputFormatter.create_section_header("CHANGED FILES")
    truncated = OutputFormatter.truncate(long_text, max_line_length=100)
"""

import re
from dataclasses import dataclass

try:
    from sandroid.config import get_config
except ImportError:
    get_config = None


def _get_display_value(field: str, default):
    """Read a display config value with fallback."""
    try:
        if get_config is not None:
            return getattr(get_config().display, field, default)
    except Exception:
        pass
    return default


class Colors:
    """ANSI color codes for terminal output.

    This class provides centralized ANSI escape codes for consistent
    colored output across all Sandroid modules. Previously duplicated
    as 'Bcolors' in changedfiles.py, deletedfiles.py, newfiles.py,
    processes.py, and sockets.py.

    Example:
        print(f"{Colors.OKGREEN}Success{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.WARNING}Warning{Colors.ENDC}")
    """

    # Foreground colors
    HEADER = "\033[95m"  # Magenta
    OKBLUE = "\033[94m"  # Blue
    OKCYAN = "\033[96m"  # Cyan
    OKGREEN = "\033[92m"  # Green
    WARNING = "\033[93m"  # Yellow
    FAIL = "\033[91m"  # Red

    # Text styles
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Reset
    ENDC = "\033[0m"

    # Aliases for backwards compatibility
    @classmethod
    def reset(cls) -> str:
        """Return the reset code (alias for ENDC)."""
        return cls.ENDC


@dataclass
class TruncationResult:
    """Result of a text truncation operation.

    Attributes:
        text: The truncated text
        was_truncated: Whether the text was actually truncated
        lines_cut: Number of lines that were removed (if any)
        chars_cut: Total characters that were removed (approximate)
    """

    text: str
    was_truncated: bool
    lines_cut: int = 0
    chars_cut: int = 0


class OutputFormatter:
    """Utility class for formatting output text.

    Provides static methods for creating consistent section headers/footers,
    truncating long text, and highlighting patterns in text.

    All methods are stateless and can be used without instantiation.
    """

    # Default formatting constants
    _DEFAULT_LINE_LENGTH_CUTOFF = 150
    _DEFAULT_LINE_NUMBER_CUTOFF = 50
    _DEFAULT_SECTION_WIDTH = 60
    _DEFAULT_FILE_PATH_MAX_LENGTH = 80
    _DEFAULT_TIMESTAMP_HIGHLIGHT_MARGIN = 100

    @staticmethod
    def create_section_header(
        title: str,
        color: str = Colors.OKBLUE,
        width: int | None = None,
        bold: bool = True,
    ) -> str:
        r"""Create a formatted section header with title.

        Args:
            title: The section title to display
            color: ANSI color code to use (default: Colors.OKBLUE)
            width: Total width of the header line (default: from config or 60)
            bold: Whether to make the header bold (default: True)

        Returns:
            Formatted header string with color codes

        Example:
            >>> OutputFormatter.create_section_header("CHANGED FILES")
            '\\n—————————————CHANGED FILES————————————————\\n'
        """
        if width is None:
            width = _get_display_value(
                "section_width", OutputFormatter._DEFAULT_SECTION_WIDTH
            )

        # Calculate padding
        title_with_padding = f" {title} "
        padding_total = width - len(title_with_padding)
        padding_left = padding_total // 2
        padding_right = padding_total - padding_left

        # Build header
        line = "—" * padding_left + title_with_padding + "—" * padding_right

        bold_code = Colors.BOLD if bold else ""
        return f"\n{color}{bold_code}{line}\n{Colors.ENDC}{color}"

    @staticmethod
    def create_section_footer(
        color: str = Colors.OKBLUE,
        width: int | None = None,
        bold: bool = True,
    ) -> str:
        """Create a formatted section footer.

        Args:
            color: ANSI color code to use (default: Colors.OKBLUE)
            width: Total width of the footer line (default: from config or 60)
            bold: Whether to make the footer bold (default: True)

        Returns:
            Formatted footer string with color codes
        """
        if width is None:
            width = _get_display_value(
                "section_width", OutputFormatter._DEFAULT_SECTION_WIDTH
            )

        bold_code = Colors.BOLD if bold else ""
        line = "—" * width
        return f"{bold_code}{line}\n{Colors.ENDC}"

    @staticmethod
    def truncate(
        input_string: str,
        line_length_cutoff: int | None = None,
        line_number_cutoff: int | None = None,
    ) -> str:
        r"""Truncate a string to fit within length and line limits.

        Truncates both individual line lengths and total number of lines.
        Lines that exceed the length limit get '[...]' appended.
        If the total number of lines exceeds the limit, a summary is added.

        Args:
            input_string: The string to truncate
            line_length_cutoff: Maximum characters per line (default: from config or 150)
            line_number_cutoff: Maximum number of lines (default: from config or 50)

        Returns:
            The truncated string with truncation indicators

        Example:
            >>> long_text = "A" * 200 + "\\n" * 100
            >>> result = OutputFormatter.truncate(long_text, 50, 10)
            >>> "[...]" in result
            True
        """
        if not input_string:
            return ""

        if line_length_cutoff is None:
            line_length_cutoff = _get_display_value(
                "line_length_cutoff", OutputFormatter._DEFAULT_LINE_LENGTH_CUTOFF
            )
        if line_number_cutoff is None:
            line_number_cutoff = _get_display_value(
                "line_number_cutoff", OutputFormatter._DEFAULT_LINE_NUMBER_CUTOFF
            )

        output_lines = []
        lines = input_string.splitlines()

        for line in lines[:line_number_cutoff]:
            if len(line) > line_length_cutoff:
                output_lines.append(line[:line_length_cutoff] + "[...]")
            else:
                output_lines.append(line)

        output = "\n".join(output_lines)

        # Add summary if lines were cut
        total_lines = len(lines)
        if total_lines > line_number_cutoff:
            number_of_cut_lines = total_lines - line_number_cutoff
            output += (
                f"\n\t[{number_of_cut_lines} lines have been cut here for brevity]"
            )

        return output

    @staticmethod
    def truncate_detailed(
        input_string: str,
        line_length_cutoff: int | None = None,
        line_number_cutoff: int | None = None,
    ) -> TruncationResult:
        """Truncate a string and return detailed information about the truncation.

        Similar to truncate() but returns a TruncationResult with metadata
        about what was truncated.

        Args:
            input_string: The string to truncate
            line_length_cutoff: Maximum characters per line (default: from config or 150)
            line_number_cutoff: Maximum number of lines (default: from config or 50)

        Returns:
            TruncationResult with truncated text and metadata
        """
        if not input_string:
            return TruncationResult(text="", was_truncated=False)

        if line_length_cutoff is None:
            line_length_cutoff = _get_display_value(
                "line_length_cutoff", OutputFormatter._DEFAULT_LINE_LENGTH_CUTOFF
            )
        if line_number_cutoff is None:
            line_number_cutoff = _get_display_value(
                "line_number_cutoff", OutputFormatter._DEFAULT_LINE_NUMBER_CUTOFF
            )

        lines = input_string.splitlines()
        total_lines = len(lines)
        total_chars = len(input_string)

        output_lines = []
        chars_in_output = 0

        for line in lines[:line_number_cutoff]:
            if len(line) > line_length_cutoff:
                truncated_line = line[:line_length_cutoff] + "[...]"
                output_lines.append(truncated_line)
                chars_in_output += line_length_cutoff
            else:
                output_lines.append(line)
                chars_in_output += len(line)

        output = "\n".join(output_lines)
        lines_cut = max(0, total_lines - line_number_cutoff)

        if lines_cut > 0:
            output += f"\n\t[{lines_cut} lines have been cut here for brevity]"

        was_truncated = lines_cut > 0 or chars_in_output < sum(
            len(l) for l in lines[:line_number_cutoff]
        )

        return TruncationResult(
            text=output,
            was_truncated=was_truncated,
            lines_cut=lines_cut,
            chars_cut=max(0, total_chars - chars_in_output),
        )

    @staticmethod
    def highlight_timestamps(
        text: str,
        rest_color: str,
        action_time: int,
        action_duration: int = 0,
        highlight_color: str = Colors.WARNING,
        margin: int | None = None,
    ) -> str:
        """Highlight Unix timestamps within a time range in the text.

        Timestamps that fall within [action_time - margin, action_time + duration + margin]
        will be highlighted with the specified color.

        Args:
            text: The input text to process
            rest_color: The color to return to after the highlight
            action_time: The central Unix timestamp to highlight around
            action_duration: Duration of the action window (default: 0)
            highlight_color: Color to use for highlights (default: Colors.WARNING)
            margin: Margin around action_time to include (default: from config or 100)

        Returns:
            The text with highlighted timestamps

        Note:
            This is useful for highlighting timestamps in forensic output
            that correspond to the current analysis window.
        """
        if margin is None:
            margin = _get_display_value(
                "timestamp_highlight_margin",
                OutputFormatter._DEFAULT_TIMESTAMP_HIGHLIGHT_MARGIN,
            )

        if not text or action_time <= 0:
            return text

        # Build list of timestamps to highlight
        start = action_time - margin
        end = action_time + action_duration + margin

        # Create regex pattern for the timestamp range
        highlight_list = [str(i) for i in range(start, end + 1)]
        if not highlight_list:
            return text

        # Build regex pattern with word boundaries
        highlight_pattern = r"\b(?:" + "|".join(highlight_list) + r")\b"

        # Replace with highlighted version
        replacement = f"{highlight_color}\\g<0>{Colors.ENDC}{rest_color}"
        return re.sub(highlight_pattern, replacement, text)

    @staticmethod
    def wrap_in_box(
        text: str,
        title: str | None = None,
        color: str = Colors.OKBLUE,
        width: int | None = None,
    ) -> str:
        """Wrap text in a simple ASCII box.

        Args:
            text: The text to wrap
            title: Optional title for the box
            color: Color for the box border
            width: Width of the box (default: from config or 60)

        Returns:
            Text wrapped in a colored ASCII box
        """
        if width is None:
            width = _get_display_value(
                "box_width", OutputFormatter._DEFAULT_SECTION_WIDTH
            )

        lines = text.splitlines()

        # Calculate content width
        content_width = width - 4  # Account for borders and padding

        # Build the box
        top_border = "+" + "-" * (width - 2) + "+"
        bottom_border = top_border

        result = [f"{color}{top_border}{Colors.ENDC}"]

        if title:
            title_line = f"| {title.center(content_width)} |"
            result.append(f"{color}{title_line}{Colors.ENDC}")
            result.append(f"{color}|{'-' * (width - 2)}|{Colors.ENDC}")

        for line in lines:
            # Truncate line if needed
            if len(line) > content_width:
                line = line[: content_width - 3] + "..."
            padded_line = f"| {line.ljust(content_width)} |"
            result.append(f"{color}{padded_line}{Colors.ENDC}")

        result.append(f"{color}{bottom_border}{Colors.ENDC}")

        return "\n".join(result)

    @staticmethod
    def format_file_path(
        path: str,
        max_length: int | None = None,
        color: str | None = None,
    ) -> str:
        """Format a file path, optionally truncating from the middle.

        Args:
            path: The file path to format
            max_length: Maximum length of the formatted path (default: from config or 80)
            color: Optional color to apply

        Returns:
            Formatted file path string
        """
        if max_length is None:
            max_length = _get_display_value(
                "file_path_max_length", OutputFormatter._DEFAULT_FILE_PATH_MAX_LENGTH
            )

        if len(path) <= max_length:
            formatted = path
        else:
            # Truncate from the middle, keeping filename
            keep_chars = max_length - 5  # Account for "[...]"
            start_chars = keep_chars // 3
            end_chars = keep_chars - start_chars
            formatted = path[:start_chars] + "[...]" + path[-end_chars:]

        if color:
            return f"{color}{formatted}{Colors.ENDC}"
        return formatted


# Backwards compatibility aliases
Bcolors = Colors  # Alias for modules still using the old name


__all__ = [
    "Bcolors",  # Backwards compatibility
    "Colors",
    "OutputFormatter",
    "TruncationResult",
]
