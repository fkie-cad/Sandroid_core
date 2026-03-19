"""Clipboard utility module for Sandroid.

This module provides cross-platform clipboard functionality that works
both inside and outside of the TUI context. It handles multiple clipboard
backends with graceful fallbacks.

Supported platforms:
    - macOS: Uses pbcopy
    - Linux: Tries xclip, xsel, then wl-copy (Wayland)
    - Windows: Uses clip command

Optional dependencies:
    - pyperclip: If installed, provides additional clipboard support
"""

import logging
import platform
import shutil
import subprocess
from collections.abc import Callable

logger = logging.getLogger(__name__)


def copy_to_clipboard(
    text: str,
    *,
    textual_copy_fn: Callable[[str], None] | None = None,
) -> bool:
    """Copy text to system clipboard using OS-native commands.

    This function attempts multiple clipboard methods in order:
    1. Textual's native copy_to_clipboard (OSC 52) if provided
    2. pyperclip library if installed
    3. OS-specific clipboard commands as fallback

    Args:
        text: Text to copy to clipboard. Empty strings return False.
        textual_copy_fn: Optional Textual app's copy_to_clipboard method.
            When provided, OSC 52 escape sequences will be tried first.
            This is useful when running inside a Textual TUI.

    Returns:
        True if copy succeeded via at least one method, False otherwise.

    Examples:
        >>> # Standalone usage (outside TUI)
        >>> copy_to_clipboard("Hello, World!")
        True

        >>> # Inside a Textual app
        >>> copy_to_clipboard("Hello", textual_copy_fn=self.copy_to_clipboard)
        True
    """
    if not text:
        return False

    osc52_attempted = False

    # Try Textual's native clipboard first (uses OSC 52)
    if textual_copy_fn is not None:
        try:
            textual_copy_fn(text)
            # OSC 52 is silent - we assume success but can't verify
            # Continue to OS-native as a backup verification
            osc52_attempted = True
        except Exception as e:
            logger.debug(f"Textual clipboard failed: {e}")

    # Try pyperclip if available
    if _copy_with_pyperclip(text):
        return True

    # OS-native fallbacks
    if _copy_with_os_native(text):
        return True

    # If OSC 52 was attempted, consider it a success
    # (we can't verify OSC 52 worked, but it's better than nothing)
    return osc52_attempted


def _copy_with_pyperclip(text: str) -> bool:
    """Try to copy using pyperclip library.

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if pyperclip is available and copy succeeded, False otherwise.
    """
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except ImportError:
        logger.debug("pyperclip not installed, skipping")
        return False
    except Exception as e:
        logger.debug(f"pyperclip copy failed: {e}")
        return False


def _copy_with_os_native(text: str) -> bool:
    """Copy text using OS-native clipboard commands.

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    system = platform.system()

    try:
        if system == "Darwin":  # macOS
            return _copy_macos(text)
        if system == "Linux":
            return _copy_linux(text)
        if system == "Windows":
            return _copy_windows(text)
        logger.debug(f"Unsupported platform for clipboard: {system}")
        return False
    except Exception as e:
        logger.debug(f"OS-native clipboard copy failed: {e}")
        return False


def _copy_macos(text: str) -> bool:
    """Copy text to clipboard on macOS using pbcopy.

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    try:
        process = subprocess.Popen(
            ["pbcopy"],
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        process.communicate(input=text.encode("utf-8"))
        return process.returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"pbcopy error: {e}")
        return False


def _copy_linux(text: str) -> bool:
    """Copy text to clipboard on Linux.

    Tries multiple clipboard tools in order:
    1. xclip (X11)
    2. xsel (X11)
    3. wl-copy (Wayland)

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    clipboard_commands = [
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["wl-copy"],
    ]

    for cmd in clipboard_commands:
        if shutil.which(cmd[0]):
            try:
                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                process.communicate(input=text.encode("utf-8"))
                if process.returncode == 0:
                    return True
            except (OSError, subprocess.SubprocessError) as e:
                logger.debug(f"{cmd[0]} clipboard error: {e}")
                continue

    return False


def _copy_windows(text: str) -> bool:
    """Copy text to clipboard on Windows using clip command.

    Args:
        text: Text to copy to clipboard.

    Returns:
        True if copy succeeded, False otherwise.
    """
    try:
        process = subprocess.Popen(
            ["clip"],
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=True,
        )
        process.communicate(input=text.encode("utf-16"))
        return process.returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"clip error: {e}")
        return False


def is_clipboard_available() -> bool:
    """Check if clipboard functionality is available on this system.

    This function checks for the presence of clipboard tools without
    actually copying anything.

    Returns:
        True if at least one clipboard method is available.
    """
    # Check for pyperclip
    try:
        import pyperclip

        # pyperclip has its own detection
        pyperclip.determine_clipboard()
        return True
    except Exception:
        pass

    # Check for OS-native tools
    system = platform.system()

    if system == "Darwin":
        return shutil.which("pbcopy") is not None
    if system == "Linux":
        return any(
            shutil.which(cmd) is not None for cmd in ["xclip", "xsel", "wl-copy"]
        )
    if system == "Windows":
        return shutil.which("clip") is not None

    return False
