"""ADB utility functions for error handling and stderr filtering.

This module provides consistent handling of ADB command output,
distinguishing benign informational messages from actionable errors.
"""

import logging
import os
import re
import shlex
import subprocess

logger = logging.getLogger(__name__)


def quote_host_arg(arg: str, windows: bool | None = None) -> str:
    """Quote one argument for the *host* shell used by ``shell=True``.

    ``Adb.send_adb_command`` runs its command line through the host shell
    (``/bin/sh`` on POSIX, ``cmd.exe`` on Windows), so host-side values that
    may contain spaces or metacharacters (the adb executable path, local file
    paths) must be quoted with that shell's rules: ``shlex.quote`` on POSIX
    (a no-op for plain paths such as ``/usr/bin/adb``), double quotes on
    Windows (``cmd.exe`` does not understand single quotes).

    Args:
        arg: The argument to quote.
        windows: Force Windows (True) or POSIX (False) rules; defaults to the
            running platform.

    Returns:
        The quoted argument.
    """
    if windows is None:
        windows = os.name == "nt"
    if windows:
        return subprocess.list2cmdline([arg])
    return shlex.quote(arg)


# ---------------------------------------------------------------------------
# Device-shell argument safety
#
# ``Adb.send_adb_command`` runs its command line through the HOST shell, and
# ``adb shell`` then hands the joined arguments to the DEVICE shell. A value
# that is not under our control (an AI tool argument, a device filename, a
# package/snapshot name restored from a session) must therefore be safe for
# BOTH shells. These helpers are the single place that encodes that rule; core
# sinks use them instead of interpolating raw values.
# ---------------------------------------------------------------------------

#: Android's package-identifier format: two or more dot-separated segments,
#: each starting with a letter and containing only letters/digits/underscore.
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

#: Emulator snapshot names Sandroid accepts. Snapshot names become directory
#: names under ``<avd>/snapshots/`` and words on the emulator console, so only
#: a conservative charset is allowed and a leading ``-``/``.`` (option-like,
#: ``..``) is rejected.
SNAPSHOT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


def device_shell_arg(arg: str) -> str:
    """Quote ``arg`` as ONE literal word for an ``adb shell`` command.

    The value is quoted for the device shell first and the result again for
    the host shell, so neither shell interprets metacharacters in it.
    """
    return quote_host_arg(shlex.quote(arg))


def device_glob_arg(pattern: str) -> str:
    """Quote a device path *pattern* for ``adb shell``, keeping ``*``/``?``.

    Every literal run of the pattern is quoted for the device shell, while the
    glob characters stay bare so the device shell still expands them; the
    whole word is then quoted for the host shell. ``'/data/a b'*`` style
    output globs exactly like the unquoted pattern did for safe paths.
    """
    parts = re.split(r"([*?])", pattern)
    device_word = "".join(
        p if p in ("*", "?") else (shlex.quote(p) if p else "") for p in parts
    )
    return quote_host_arg(device_word)


def device_shell_command(command: str) -> str:
    """Return ``shell <command>`` with *command* passed intact to the device.

    *command* is a device-shell command line (pipes, redirects and quoting
    are interpreted by the DEVICE shell); it is quoted as one word for the
    host shell so nothing in it runs on the host. Any untrusted value inside
    *command* must itself be quoted with :func:`shlex.quote`.
    """
    return "shell " + quote_host_arg(command)


def is_valid_package_name(name: object) -> bool:
    """True if *name* is a string in Android's package-identifier format."""
    return isinstance(name, str) and bool(PACKAGE_NAME_RE.match(name))


def validate_package_name(name: object) -> str:
    """Return *name* if it is a valid Android package name, else raise.

    Raises:
        ValueError: *name* is not in Android's package-identifier format.
    """
    if not is_valid_package_name(name):
        raise ValueError(
            f"invalid package name {name!r}: must match Android's package "
            "identifier format (e.g. 'com.example.app')"
        )
    return name  # type: ignore[return-value]


def validate_snapshot_name(name: object) -> str:
    """Return *name* (``str``/``bytes``) as ``str`` if it is a safe snapshot name.

    Raises:
        ValueError: *name* contains characters outside ``[A-Za-z0-9._-]``,
            starts with ``-``/``.``, or is empty.
    """
    if isinstance(name, bytes):
        try:
            name = name.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(f"invalid snapshot name {name!r}") from None
    if not isinstance(name, str) or not SNAPSHOT_NAME_RE.match(name):
        raise ValueError(
            f"invalid snapshot name {name!r}: use letters, digits, '.', '_' "
            "or '-' (not starting with '.' or '-')"
        )
    return name


def validate_pid(pid: object) -> int:
    """Return *pid* as a positive ``int`` (accepts ``int`` or digit strings).

    Raises:
        ValueError: *pid* is not a positive integer.
    """
    is_number = isinstance(pid, (int, str)) and not isinstance(pid, bool)
    text = str(pid).strip() if is_number else ""
    if not re.fullmatch(r"[0-9]+", text) or int(text) <= 0:
        raise ValueError(f"invalid pid {pid!r}: must be a positive integer")
    return int(text)


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
        # ``get-state`` is a reachability probe: "device not found" is its
        # expected answer while a snapshot loads or the emulator boots, and
        # every caller handles it -- not something to warn the user about.
        if is_adb_error_actionable(stderr) and "get-state" not in command:
            logger.warning(f"ADB command warning ({command}): {stderr.strip()}")
        else:
            logger.debug(f"ADB command info ({command}): {stderr.strip()}")
    elif log_level <= logging.DEBUG:
        logger.debug(f"ADB command success: {command}")
