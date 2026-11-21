"""Utility functions for forensic analysis.

This module contains shared helper functions used across the forensic
service modules to avoid code duplication.

Usage:
    from sandroid.services.forensic_utils import is_wal_or_journal
"""

import re

# Pre-compiled patterns for filesystem parsing
TIME_PATTERN = re.compile(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
#: One ``ls -l --full-time`` entry: the timestamp column (date, time with
#: optional fraction, optional ``+0100`` zone) and *everything* after it as
#: the name, so names with spaces (WebView's ``Web Data``, ``Session
#: Storage``) are kept whole.
LS_FULL_TIME_ENTRY = re.compile(
    r"(?P<timestamp>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?(?: [+-]\d{4})?)"
    r" (?P<name>.+)$"
)
DIR_PATTERN = re.compile(r"/.*:$")

# WAL/journal file suffixes
_WAL_SUFFIX = "-wal"
_JOURNAL_SUFFIX = "-journal"
#: The WAL index: rebuilt by SQLite, rewritten on every read, so never
#: watched or pulled on its own (its database row stands for it).
_SHM_SUFFIX = "-shm"


def is_wal_or_journal(file_path: str) -> bool:
    """Check if a file is a SQLite companion (WAL, journal or WAL index).

    SQLite databases use Write-Ahead Logging (WAL) and journal files
    for transaction management, plus the ``-shm`` WAL index. These
    companion files are excluded from spotlight monitoring (watch and
    pull); the database's own entry stands for them.

    Args:
        file_path: Path or filename to check.

    Returns:
        True if the file ends with '-wal', '-journal' or '-shm'.
    """
    return file_path.endswith((_WAL_SUFFIX, _JOURNAL_SUFFIX, _SHM_SUFFIX))


def get_parent_db_path(file_path: str) -> str | None:
    """Get the parent database path for a WAL or journal file.

    Given a WAL or journal companion file, returns the path to the
    parent SQLite database file.

    Args:
        file_path: Path to a WAL or journal file.

    Returns:
        Path to parent database, or None if not a WAL/journal file.
    """
    if file_path.endswith(_WAL_SUFFIX):
        return file_path[: -len(_WAL_SUFFIX)]
    if file_path.endswith(_JOURNAL_SUFFIX):
        return file_path[: -len(_JOURNAL_SUFFIX)]
    return None


__all__ = [
    "DIR_PATTERN",
    "LS_FULL_TIME_ENTRY",
    "TIME_PATTERN",
    "get_parent_db_path",
    "is_wal_or_journal",
]
