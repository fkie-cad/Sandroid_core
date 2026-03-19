"""ADB utility functions for error handling and stderr filtering.

This module provides consistent handling of ADB command output,
distinguishing benign informational messages from actionable errors.
"""

import logging

logger = logging.getLogger(__name__)

# Benign ADB patterns that should be logged but not treated as errors
BENIGN_ADB_PATTERNS = [
    "daemon not running",
    "daemon started",
    "adb server version",
    "killing...",
    "restarting adbd as root",
    "already running as root",
    # Pull/push success messages go to stderr
    "file pulled",
    "file pushed",
    "files pulled",
    "files pushed",
]

# Error indicators that always indicate a real problem
ADB_ERROR_INDICATORS = [
    "no devices/emulators found",
    "no devices found",
    "device offline",
    "permission denied",
    "error:",
    "failed",
    "cannot",
    "INSTALL_FAILED",
]


def is_adb_error_actionable(stderr: str) -> bool:
    """Check if ADB stderr indicates a real error vs benign message.

    Filters common benign ADB messages (daemon startup, version info)
    from actionable errors (device offline, permission denied).

    Args:
        stderr: The stderr output from ADB command

    Returns:
        True if this is an actionable error requiring user attention,
        False if benign (should be logged but not displayed as error)
    """
    if not stderr:
        return False

    stderr_lower = stderr.lower()

    # First check for benign patterns - if found, not actionable
    for pattern in BENIGN_ADB_PATTERNS:
        if pattern in stderr_lower:
            logger.debug(f"ADB benign message filtered: {stderr.strip()}")
            return False

    # Check for error indicators
    for indicator in ADB_ERROR_INDICATORS:
        if indicator in stderr_lower:
            return True

    # If stderr has content but no known patterns, treat as potential error
    # but log for debugging
    if stderr.strip():
        logger.debug(f"ADB unknown stderr: {stderr.strip()}")
        return True

    return False


def format_adb_error(
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int | None = None,
) -> str:
    """Format ADB error with full technical context.

    Creates a detailed error message suitable for forensic analysts,
    including command, output, and exit code.

    Args:
        command: The ADB command that was executed
        stdout: Standard output from the command
        stderr: Standard error from the command
        exit_code: Process exit code if available

    Returns:
        Formatted error string with full context
    """
    parts = [f"ADB command failed: {command}"]

    if exit_code is not None:
        parts.append(f"Exit code: {exit_code}")

    if stderr and stderr.strip():
        parts.append(f"stderr: {stderr.strip()}")

    if stdout and stdout.strip():
        # Truncate long stdout
        stdout_preview = stdout.strip()[:500]
        if len(stdout.strip()) > 500:
            stdout_preview += "... (truncated)"
        parts.append(f"stdout: {stdout_preview}")

    return "\n".join(parts)


def detect_adb_pull_error(output: str, error: str) -> str | None:
    """Check if ADB pull output indicates an error.

    Centralised check for the most common ADB pull failure markers.

    Args:
        output: stdout from the ADB command.
        error: stderr from the ADB command.

    Returns:
        Short error description, or ``None`` when no error detected.
    """
    combined = str(output) + str(error)
    if "failed to stat remote object" in combined:
        return "File not found on device"
    if "Permission denied" in combined:
        return "Permission denied"
    if "error:" in combined.lower():
        return combined.strip()
    return None


def log_adb_result(
    command: str,
    stdout: str,
    stderr: str,
    log_level: int = logging.DEBUG,
) -> None:
    """Log ADB command result appropriately.

    Logs benign stderr at DEBUG level, actionable errors at WARNING.
    Always logs full stderr to file for debugging.

    Args:
        command: The ADB command that was executed
        stdout: Standard output from the command
        stderr: Standard error from the command
        log_level: Base log level for success (default DEBUG)
    """
    if stderr:
        if is_adb_error_actionable(stderr):
            logger.warning(f"ADB command warning ({command}): {stderr.strip()}")
        else:
            logger.debug(f"ADB command info ({command}): {stderr.strip()}")
    elif log_level <= logging.DEBUG:
        logger.debug(f"ADB command success: {command}")
