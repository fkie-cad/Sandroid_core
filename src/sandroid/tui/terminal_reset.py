"""Terminal reset utilities for Sandroid TUI.

This module provides terminal cleanup functions used when the TUI exits
(normally or abnormally). It handles:
- Escape sequences to disable mouse tracking and restore cursor
- ``stty sane`` fallback for complete terminal mode reset
- Hard reset for crash recovery (guardian process)

These functions are registered via ``atexit`` and signal handlers to ensure
the terminal is always left in a usable state.
"""

import subprocess
import sys

# Leaving the alternate screen also restores the cursor saved when it was
# entered. Sent a second time -- by the atexit reset, after the session
# summary was printed -- it jumped the cursor back above the summary and the
# shell prompt overwrote it. So it is sent once per process.
_ALT_SCREEN_EXIT = "\033[?1049l"

# Escape sequences that restore the terminal to a usable state.
_MODE_RESETS = (
    "\033[?1000l"  # Disable X10 mouse tracking
    "\033[?1002l"  # Disable cell motion tracking
    "\033[?1003l"  # Disable all motion tracking
    "\033[?1006l"  # Disable SGR extended mouse
    "\033[?25h"  # Show cursor
    "\033[0m"  # Reset all attributes
)
_RESET_SEQUENCES = _ALT_SCREEN_EXIT + _MODE_RESETS

_alt_screen_left = {"done": False}


def _write_reset_sequences() -> None:
    """Write terminal reset escape sequences to stdout.

    The alternate-screen exit is written only the first time (see
    ``_ALT_SCREEN_EXIT``); the mode resets every time.
    """
    try:
        # A kitty image of the device screen (Ctrl+G) would outlive the app.
        from sandroid.tui.terminal_graphics import graphics_reset_sequence

        graphics = graphics_reset_sequence()
    except Exception:
        graphics = ""
    try:
        if _alt_screen_left["done"]:
            sys.stdout.write(graphics + _MODE_RESETS)
        else:
            sys.stdout.write(graphics + _RESET_SEQUENCES)
            _alt_screen_left["done"] = True
        sys.stdout.flush()
    except Exception:
        pass


def _run_stty_sane() -> None:
    """Run ``stty sane`` as a fallback for complete terminal mode reset.

    Only available on Unix-like systems; silently skipped on Windows.
    """
    import platform

    if platform.system() == "Windows":
        return
    try:
        subprocess.run(["stty", "sane"], timeout=1, check=False)
    except Exception:
        pass


def reset_terminal() -> None:
    """Reset terminal to normal mode, disabling mouse tracking.

    This handles cleanup when the app exits abnormally.
    """
    _write_reset_sequences()
    _run_stty_sane()


def reset_terminal_hard() -> None:
    """Perform a hard terminal reset using escape sequences and stty.

    This is used by the guardian process when the TUI child exits abnormally.
    Semantically identical to :func:`reset_terminal` but kept as a separate
    entry point for crash-recovery paths.
    """
    _write_reset_sequences()
    _run_stty_sane()
