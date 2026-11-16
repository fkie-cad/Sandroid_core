"""File filtering utilities for analysis modules.

This module provides common filtering functions used across multiple
analysis modules (changedfiles, newfiles, deletedfiles) to eliminate
code duplication and ensure consistent filtering behavior.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

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


#: Directory prefixes whose contents are runtime bookkeeping, not app
#: artefacts: ART/JIT profiles (``primary.prof`` is rewritten whenever an app
#: has run for a while, so it shows up in every replay but never in the
#: app-less dry run) and the profman/dexopt scratch areas.
STRUCTURAL_NOISE_PREFIXES: tuple[str, ...] = (
    "/data/misc/profiles/",
    "/data/misc/profman/",
    # Battery-stats history chunks, rolled over on wall-clock changes (each
    # snapshot revert + clock resync starts a new, differently named one).
    "/data/system/battery-history/",
)

#: Exact files the package manager / ART rewrite on their own schedule.
STRUCTURAL_NOISE_FILES: frozenset[str] = frozenset(
    {
        "/data/system/package-dex-usage.pb",
        "/data/system/package-usage.list",
        # Records wall-clock shifts -- rewritten by every guest clock resync.
        "/data/system/monotonic_clock.xml",
    }
)

#: File-name suffixes of ART profile files (also written next to app code).
STRUCTURAL_NOISE_SUFFIXES: tuple[str, ...] = (".prof", ".prof.bak")


def is_structural_noise(file_path: str) -> bool:
    """Whether ``file_path`` is known runtime noise regardless of the dry run.

    The dry-run noise pass only catches files that change *without* the app
    running; ART profiles change *because* the app ran, so they survive the
    noise subtraction and used to head the "Changed Files" list.

    Args:
        file_path: Absolute device path.

    Returns:
        True for ART/dexopt bookkeeping files that never carry app evidence.
    """
    return (
        file_path.startswith(STRUCTURAL_NOISE_PREFIXES)
        or file_path in STRUCTURAL_NOISE_FILES
        or file_path.endswith(STRUCTURAL_NOISE_SUFFIXES)
    )


#: Curated list of well-known Android / Google Play services background paths
#: (``fnmatch`` globs; ``*`` also matches ``/``). These files change on a Play
#: image whether or not the analysed app does anything, so on a demo they
#: drowned the app's own artefacts. Matches are *not* dropped: they are moved
#: to ``Other Data -> Filtered Noise`` in the result JSON. Files of the target
#: (spotlight) app and of ``analysis.protected_packages`` are never matched.
#: Opt out with ``analysis.system_noise_filter = false``; add site-specific
#: globs with ``analysis.noise_patterns``.
DEFAULT_SYSTEM_NOISE_PATTERNS: tuple[str, ...] = (
    # --- system_server state (rewritten by the framework, not the app) ---
    "/data/system/users/*/package-restrictions.xml*",
    "/data/system/users/*/appwidgets.xml*",
    "/data/system_ce/*/recent_tasks/*",
    "/data/system_ce/*/recent_images/*",
    "/data/system/netstats/*",
    "/data/system/usagestats/*",
    "/data/system/procstats/*",
    "/data/system/dropbox/*",
    "/data/system/graphicsstats/*",
    "/data/system/batterystats*",
    # --- mainline modules: traffic counters, permission/role bookkeeping ---
    "/data/misc/apexdata/com.android.tethering/netstats/*",
    "/data/misc/apexdata/com.android.permission/*",
    "/data/misc_de/*/apexdata/com.android.permission/*",
    # --- Google Play services / Play Store and their telemetry ---
    "/data/*/com.google.android.gms/*",
    "/data/*/com.google.android.gsf/*",
    "/data/*/com.android.vending/*",
    # --- Google system apps that sync or log in the background ---
    "/data/*/com.google.android.apps.wellbeing/*",
    "/data/*/com.google.android.as/*",
    "/data/*/com.google.android.as.oss/*",
    "/data/*/com.google.android.inputmethod.latin/*",
    "/data/*/com.google.android.webview/*",
    "/data/*/com.google.android.apps.nexuslauncher/*",
    "/data/*/com.google.android.googlequicksearchbox/*",
    "/data/*/com.android.providers.calendar/shared_prefs/sanity.xml",
    # PRIMES "flight records" (calendar, deskclock, ...)
    "/data/*/files/flight_records/*",
)

#: Characters that may follow a package name inside a path component
#: (``org.wikipedia.xml``, ``org.wikipedia_preferences.xml``,
#: ``org.wikipedia-1==`` under ``/data/app``).
_PACKAGE_COMPONENT_SEPARATORS = (".", "_", "-", ":")


def path_belongs_to_package(file_path: str, package: str) -> bool:
    """Whether ``file_path`` has a path component naming ``package``.

    Errs on the side of *protecting* a file: any component equal to the
    package name or starting with it plus a separator counts.
    """
    if not package:
        return False
    prefixes = tuple(package + sep for sep in _PACKAGE_COMPONENT_SEPARATORS)
    return any(
        part == package or part.startswith(prefixes)
        for part in file_path.split("/")
    )


@dataclass
class SystemNoiseFilter:
    """Hide well-known system/GMS background files, transparently.

    Attributes:
        enabled: Apply the patterns at all (``analysis.system_noise_filter``).
        patterns: ``fnmatch`` globs (defaults plus ``analysis.noise_patterns``).
        protected_packages: Packages whose files are never filtered -- the
            spotlight/target app plus ``analysis.protected_packages``.
    """

    enabled: bool = True
    patterns: tuple[str, ...] = DEFAULT_SYSTEM_NOISE_PATTERNS
    protected_packages: tuple[str, ...] = field(default_factory=tuple)

    def match(self, file_path: str) -> str | None:
        """Return the pattern ``file_path`` is filtered by, or ``None``."""
        if not self.enabled:
            return None
        if any(path_belongs_to_package(file_path, p) for p in self.protected_packages):
            return None
        for pattern in self.patterns:
            if fnmatch.fnmatchcase(file_path, pattern):
                return pattern
        return None

    def split(self, files: list[str]) -> tuple[list[str], dict[str, str]]:
        """Split ``files`` into ``(kept, {filtered_path: matching_pattern})``."""
        kept: list[str] = []
        filtered: dict[str, str] = {}
        for file_path in files:
            pattern = self.match(file_path)
            if pattern is None:
                kept.append(file_path)
            else:
                filtered[file_path] = pattern
        return kept, filtered


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
        if is_structural_noise(file_path):
            continue
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
