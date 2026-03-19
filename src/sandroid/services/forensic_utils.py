"""Utility functions for forensic analysis.

This module contains shared helper functions used across the forensic
service modules to avoid code duplication.

Usage:
    from sandroid.services.forensic_utils import is_wal_or_journal
"""

import re

# Pre-compiled patterns for filesystem parsing
TIME_PATTERN = re.compile(r"\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d")
DIR_PATTERN = re.compile(r"/.*:$")

# WAL/journal file suffixes
_WAL_SUFFIX = "-wal"
_JOURNAL_SUFFIX = "-journal"


def is_wal_or_journal(file_path: str) -> bool:
    """Check if a file is a SQLite WAL or journal file.

    SQLite databases use Write-Ahead Logging (WAL) and journal files
    for transaction management. These companion files are typically
    excluded from spotlight monitoring and grouped with their parent
    database during change detection.

    Args:
        file_path: Path or filename to check.

    Returns:
        True if the file ends with '-wal' or '-journal'.
    """
    return file_path.endswith(_WAL_SUFFIX) or file_path.endswith(_JOURNAL_SUFFIX)


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
    "TIME_PATTERN",
    "get_parent_db_path",
    "is_wal_or_journal",
]
