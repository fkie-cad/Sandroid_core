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

# Escape sequences that restore the terminal to a usable state.
_RESET_SEQUENCES = (
    "\033[?1049l"  # Exit alternate screen
    "\033[?1000l"  # Disable X10 mouse tracking
    "\033[?1002l"  # Disable cell motion tracking
    "\033[?1003l"  # Disable all motion tracking
    "\033[?1006l"  # Disable SGR extended mouse
    "\033[?25h"  # Show cursor
    "\033[0m"  # Reset all attributes
)


def _write_reset_sequences() -> None:
    """Write terminal reset escape sequences to stdout."""
    try:
        sys.stdout.write(_RESET_SEQUENCES)
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
