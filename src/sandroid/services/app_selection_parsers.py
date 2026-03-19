"""Package info parsing for App Selection Service.

Extracts structured information from Android `dumpsys package` output
using a unified, data-driven regex approach instead of repeated
inline regex blocks.
"""

import logging
import re
from dataclasses import dataclass, fields
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PatternSpec:
    """Specification for a single regex extraction."""

    field_name: str
    pattern: str
    convert: type = str  # str or int


# Each spec maps a PackageInfo field to a regex pattern and an optional
# type converter.  The order does not matter.
PACKAGE_INFO_PATTERNS: tuple[_PatternSpec, ...] = (
    _PatternSpec("version_name", r"versionName=(\S+)"),
    _PatternSpec("version_code", r"versionCode=(\d+)", int),
    _PatternSpec("target_sdk", r"targetSdk=(\d+)", int),
    _PatternSpec("min_sdk", r"minSdk=(\d+)", int),
    _PatternSpec("apk_path", r"codePath=(\S+)"),
    _PatternSpec("data_dir", r"dataDir=(\S+)"),
    _PatternSpec("install_date", r"firstInstallTime=(.+)"),
)


class PackageInfoParser:
    """Parse `dumpsys package` output into PackageInfo field values.

    Usage::

        parser = PackageInfoParser()
        values = parser.parse(dumpsys_output)
        # values == {"version_name": "1.2.3", "version_code": 42, ...}
    """

    def __init__(
        self,
        patterns: tuple[_PatternSpec, ...] = PACKAGE_INFO_PATTERNS,
    ) -> None:
        self._patterns = patterns
        # Pre-compile regexes for efficiency
        self._compiled: list[tuple[_PatternSpec, re.Pattern[str]]] = [
            (spec, re.compile(spec.pattern)) for spec in self._patterns
        ]

    def parse(self, dumpsys_output: str) -> dict[str, Any]:
        """Extract all known fields from *dumpsys_output*.

        Returns:
            Dictionary of field_name -> parsed value for every pattern
            that matched.  Fields that did not match are omitted.
        """
        result: dict[str, Any] = {}
        for spec, compiled in self._compiled:
            match = compiled.search(dumpsys_output)
            if match:
                raw = match.group(1)
                # install_date can have trailing whitespace
                if spec.field_name == "install_date":
                    raw = raw.strip()
                try:
                    result[spec.field_name] = spec.convert(raw)
                except (ValueError, TypeError):
                    logger.debug(
                        "Could not convert %r to %s for field %s",
                        raw,
                        spec.convert.__name__,
                        spec.field_name,
                    )
        return result

    def is_user_app(self, dumpsys_output: str) -> bool:
        """Determine whether the package is a user-installed app."""
        return "flags=" in dumpsys_output and "SYSTEM" not in dumpsys_output.upper()


# Module-level singleton for convenience
_default_parser: PackageInfoParser | None = None


def get_parser() -> PackageInfoParser:
    """Return a module-level singleton parser."""
    global _default_parser
    if _default_parser is None:
        _default_parser = PackageInfoParser()
    return _default_parser
