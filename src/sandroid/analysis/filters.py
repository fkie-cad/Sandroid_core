"""File filtering utilities for analysis modules.

This module provides common filtering functions used across multiple
analysis modules (changedfiles, newfiles, deletedfiles) to eliminate
code duplication and ensure consistent filtering behavior.
"""

from sandroid.core import file_diff


def intersect_file_lists(file_lists: list[list[str]]) -> list[str]:
    """Intersect multiple file lists to get files that appear in all lists.

    This is used to find files that consistently appear across multiple
    analysis runs, filtering out files that only appear in some runs.

    Args:
        file_lists: List of file path lists from multiple runs.

    Returns:
        List of file paths that appear in ALL input lists.

    Example:
        >>> lists = [
        ...     ["/data/file1", "/data/file2", "/data/file3"],
        ...     ["/data/file1", "/data/file2"],
        ...     ["/data/file1", "/data/file2", "/data/file4"],
        ... ]
        >>> intersect_file_lists(lists)
        ['/data/file1', '/data/file2']
    """
    if not file_lists:
        return []

    # Start with the first list as a set
    result: set[str] = set(file_lists[0])

    # Intersect with each subsequent list
    for file_list in file_lists[1:]:
        result &= set(file_list)

    return list(result)


def filter_noise_files(
    files: list[str],
    noise_files: dict[str, str],
    preserve_sqlite_xml: bool = True,
) -> list[str]:
    """Filter out noise files while optionally preserving SQLite and XML files.

    Noise files are files that change regardless of the analysis being performed
    (e.g., system log files, cache files). This function removes them from the
    results while preserving important file types that should always be analyzed.

    Args:
        files: List of file paths to filter.
        noise_files: Dictionary of noise file paths (keys are paths).
        preserve_sqlite_xml: If True, SQLite and XML files are kept even if
            they appear in the noise files list. Default is True.

    Returns:
        Filtered list of file paths with noise files removed.

    Example:
        >>> files = ["/data/app.db", "/data/cache.tmp", "/data/settings.xml"]
        >>> noise = {"/data/app.db": "hash", "/data/cache.tmp": "hash"}
        >>> filter_noise_files(files, noise, preserve_sqlite_xml=True)
        ['/data/app.db', '/data/settings.xml']
    """
    result: list[str] = []

    for file_path in files:
        if file_path not in noise_files:
            # File is not noise, keep it
            result.append(file_path)
        elif preserve_sqlite_xml:
            # File is noise, but check if it should be preserved
            if file_diff.is_sqlite_from_device_path(file_path) or file_path.endswith(
                ".xml"
            ):
                result.append(file_path)
            # Otherwise, file is noise and not a special type - skip it

    return result


def process_file_lists(
    file_lists: list[list[str]],
    noise_files: dict[str, str],
    whitelist_filter: callable = None,
    preserve_sqlite_xml: bool = True,
) -> list[str]:
    """Process file lists through intersection, noise filtering, and whitelist.

    This is a convenience function that combines the common processing pipeline
    used by multiple analysis modules:
    1. Intersect all file lists to get consistent files
    2. Filter out noise files (preserving SQLite/XML if specified)
    3. Apply whitelist exclusion if provided

    Args:
        file_lists: List of file path lists from multiple runs.
        noise_files: Dictionary of noise file paths.
        whitelist_filter: Optional callable to apply whitelist filtering.
            Should take a list of files and return filtered list.
        preserve_sqlite_xml: If True, preserve SQLite and XML files even
            if they appear in noise. Default is True.

    Returns:
        Processed list of file paths.

    Example:
        >>> result = process_file_lists(
        ...     file_lists=[["/data/file1", "/data/file2"]],
        ...     noise_files={},
        ...     whitelist_filter=lambda x: x,
        ... )
    """
    # Step 1: Intersect file lists
    files = intersect_file_lists(file_lists)

    # Step 2: Filter noise files
    files = filter_noise_files(
        files,
        noise_files,
        preserve_sqlite_xml=preserve_sqlite_xml,
    )

    # Step 3: Apply whitelist filter if provided
    if whitelist_filter is not None:
        files = whitelist_filter(files)

    return files


# File type checking utilities
def is_sqlite_file(path: str) -> bool:
    """Check if a file path refers to a SQLite database.

    Uses the file_diff module's implementation for consistency.

    Args:
        path: File path to check.

    Returns:
        True if the file is a SQLite database, False otherwise.
    """
    return file_diff.is_sqlite_from_device_path(path)


def is_xml_file(path: str) -> bool:
    """Check if a file path refers to an XML file.

    Args:
        path: File path to check.

    Returns:
        True if the file has an .xml extension (case-insensitive).
    """
    return path.lower().endswith(".xml")


def is_apk_file(path: str) -> bool:
    """Check if a file path refers to an APK file.

    Args:
        path: File path to check.

    Returns:
        True if the file has an .apk extension (case-insensitive).
    """
    return path.lower().endswith(".apk")


def is_text_file(path: str) -> bool:
    """Check if a file path refers to a text file.

    Args:
        path: File path to check.

    Returns:
        True if the file has a .txt extension (case-insensitive).
    """
    return path.lower().endswith(".txt")
