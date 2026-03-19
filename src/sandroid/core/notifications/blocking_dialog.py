"""Blocking dialog service for terminal and TUI modal display.

Provides blocking dialogs (warning, error, info) that overlay the terminal
and require user acknowledgment before continuing.  When the Textual TUI is
active the dialog is routed through the native ``MessageModal``; otherwise
a Rich panel (or ASCII fallback) is rendered directly.

Usage::

    from sandroid.core.notifications.blocking_dialog import BlockingDialogService

    dialog = BlockingDialogService()
    dialog.show_warning("Title", "Something happened")
    dialog.show_error("Oops", "Failed to do the thing")
"""

import logging
import sys

logger = logging.getLogger(__name__)

# Check for platform-specific terminal input handling
try:
    import termios

    TERMIOS_AVAILABLE = True
except ImportError:
    TERMIOS_AVAILABLE = False

try:
    import msvcrt

    MSVCRT_AVAILABLE = True
except ImportError:
    MSVCRT_AVAILABLE = False


class BlockingDialogService:
    """Service for displaying blocking dialogs that require user acknowledgment.

    Supports three dialog types (warning, error, info) and two rendering
    backends (Rich panel for CLI, ``MessageModal`` for TUI).

    Thread Safety:
        This service is stateless and safe to call from any thread.
    """

    def __init__(self) -> None:
        self._logger = logger

    # ------------------------------------------------------------------
    # Public convenience methods
    # ------------------------------------------------------------------

    def show_warning(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display a warning modal that requires user acknowledgment.

        Args:
            title: The title of the warning dialog.
            message: The warning message to display.
            action_hint: Optional hint about what action to take.
            action_key: Optional key that can dismiss modal and trigger action.

        Returns:
            None if Enter pressed, or the action_key if that was pressed.
        """
        return self._show_blocking_dialog(
            title=title,
            message=message,
            action_hint=action_hint,
            action_key=action_key,
            dialog_type="warning",
        )

    def show_error(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display an error modal that requires user acknowledgment.

        Args:
            title: The title of the error dialog.
            message: The error message to display.
            action_hint: Optional hint about what action to take.
            action_key: Optional key that can dismiss modal and trigger action.

        Returns:
            None if Enter pressed, or the action_key if that was pressed.
        """
        return self._show_blocking_dialog(
            title=title,
            message=message,
            action_hint=action_hint,
            action_key=action_key,
            dialog_type="error",
        )

    def show_info(
        self,
        title: str,
        message: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Display an info modal that requires user acknowledgment.

        Args:
            title: The title of the info dialog.
            message: The info message to display.
            action_hint: Optional hint about what action to take.
            action_key: Optional key that can dismiss modal and trigger action.

        Returns:
            None if Enter pressed, or the action_key if that was pressed.
        """
        return self._show_blocking_dialog(
            title=title,
            message=message,
            action_hint=action_hint,
            action_key=action_key,
            dialog_type="info",
        )

    # ------------------------------------------------------------------
    # Input helpers
    # ------------------------------------------------------------------

    def safe_input(self, prompt: str = "") -> str:
        """Safely read input from stdin with buffer flushing.

        Addresses buffering problems that occur when multiple interactive
        programs run in the same terminal session.  Flushes any pending
        stdin input before reading to prevent leftover buffered data from
        being consumed.

        Args:
            prompt: Optional prompt string to display before reading input.

        Returns:
            The user's input as a string (stripped of whitespace).
        """
        # Only attempt flushing if stdin is a TTY (interactive terminal)
        if sys.stdin.isatty():
            try:
                if TERMIOS_AVAILABLE:
                    import termios

                    termios.tcflush(sys.stdin, termios.TCIFLUSH)
                elif MSVCRT_AVAILABLE:
                    import msvcrt

                    while msvcrt.kbhit():
                        msvcrt.getch()
            except Exception as e:
                self._logger.debug(f"Could not flush stdin buffer: {e}")

        if prompt:
            print(prompt, end="", flush=True)

        try:
            return input().strip()
        except EOFError:
            return ""

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _show_blocking_dialog(
        self,
        title: str,
        message: str,
        dialog_type: str,
        action_hint: str | None = None,
        action_key: str | None = None,
    ) -> str | None:
        """Render and display a blocking dialog.

        Args:
            title: Dialog title.
            message: Dialog message.
            dialog_type: One of ``"warning"``, ``"error"``, ``"info"``.
            action_hint: Optional hint about what action to take.
            action_key: Optional key that can dismiss modal and trigger action.

        Returns:
            None if Enter pressed, or the *action_key* if that was pressed.
        """
        # Route to TUI modal when active
        if self._try_tui_dialog(title, message, action_hint, dialog_type):
            return None  # TUI mode doesn't support action_key yet

        # Style configuration for different dialog types
        styles = {
            "warning": {
                "icon": "!",
                "border_style": "yellow bold",
                "continue_style": "yellow",
            },
            "error": {
                "icon": "\u2717",
                "border_style": "red bold",
                "continue_style": "red",
            },
            "info": {
                "icon": "[i]",
                "border_style": "cyan bold",
                "continue_style": "cyan",
            },
        }
        style = styles.get(dialog_type, styles["info"])

        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.text import Text

            console = Console()
            text = Text()
            text.append(message)

            if action_hint:
                text.append("\n\n")
                text.append(action_hint, style="cyan bold")

            text.append("\n\n")
            text.append("Press Enter to continue...", style=style["continue_style"])

            panel = Panel(
                text,
                title=f"{style['icon']} {title}",
                border_style=style["border_style"],
                padding=(1, 2),
                expand=False,
            )

            print()
            console.print(panel)
            print()

            return self._wait_for_key(action_key)

        except ImportError:
            # Fallback to ASCII box if Rich is not available
            box_content = f"{message}\n"
            if action_hint:
                box_content += f"\n{action_hint}\n"
            box_content += "\nPress Enter to continue..."

            print()
            print(
                self._create_ascii_box(box_content, f"{dialog_type.upper()}: {title}")
            )

            return self._wait_for_key(action_key)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _try_tui_dialog(
        title: str,
        message: str,
        action_hint: str | None,
        dialog_type: str,
    ) -> bool:
        """Attempt to show the dialog via the TUI notification system.

        Returns True if handled by TUI, False otherwise.
        """
        try:
            from sandroid.core.notifications import show_error, show_info, show_warning
            from sandroid.core.ui_request_bus import UIRequestBus

            bus = UIRequestBus.get()
            if bus.has_active_handler():
                full_message = message
                if action_hint:
                    full_message += f"\n\n{action_hint}"
                if dialog_type == "warning":
                    show_warning(title, full_message)
                elif dialog_type == "error":
                    show_error(title, full_message)
                else:
                    show_info(title, full_message)
                return True
        except ImportError:
            pass
        return False

    @staticmethod
    def _wait_for_key(action_key: str | None) -> str | None:
        """Wait for Enter or the optional *action_key*."""
        import click

        while True:
            key = click.getchar()
            if key in ("\r", "\n"):
                return None
            if action_key and key == action_key:
                return action_key

    @staticmethod
    def _create_ascii_box(text: str, title: str) -> str:
        """Create a minimal ASCII box (fallback when Rich is unavailable)."""
        try:
            from wcwidth import wcswidth
        except ImportError:

            def wcswidth(s):
                return len(s)

        import re

        ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

        def strip_ansi(s: str) -> str:
            return ANSI_RE.sub("", s)

        def cell_width(s: str) -> int:
            w = wcswidth(s)
            return 0 if w < 0 else w

        raw_lines = text.splitlines()
        stripped_lines = [strip_ansi(ln).expandtabs(4) for ln in raw_lines]
        visible_widths = [cell_width(ln) for ln in stripped_lines]
        inner_width = (max(visible_widths) if visible_widths else 0) + 2

        stripped_title = strip_ansi(title)
        title_w = cell_width(stripped_title)
        pad_left = (inner_width - title_w) // 2
        pad_right = inner_width - title_w - pad_left

        h_line = "\u2500" * inner_width
        top = (
            f"\u250c{h_line}\u2510\n"
            f"\u2502{' ' * pad_left}{title}{' ' * pad_right}\u2502\n"
            f"\u251c{h_line}\u2524\n"
        )

        body_parts = []
        for raw, stripped in zip(raw_lines, stripped_lines, strict=False):
            pad = inner_width - cell_width(stripped)
            pad = max(pad, 0)
            body_parts.append(f"\u2502{raw}{' ' * pad}\u2502")
        body = "\n".join(body_parts)

        bottom = f"\n\u2514{h_line}\u2518"
        return f"{top}{body}{bottom}"


__all__ = [
    "BlockingDialogService",
]
